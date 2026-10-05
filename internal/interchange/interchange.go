// Package interchange 实现 EIP-3076 风格的防罚没记录互导。
//
// 合并语义（导入）：
//   - 文件必须整体可解析（JSON 完整、格式版本支持、字段结构合法），
//     任何解析错误都整体拒绝，不写入任何记录；
//   - 导入记录之间以及与现有记录之间，若构成同 target 双投 / surround 区间冲突 /
//     同 slot 不同区块，则整体拒绝（IMPORT_CONFLICT），不做部分写入；
//   - 完全重复的记录幂等合并；其余记录安全并入；
//   - 导入与签名共用同一把存储锁，结论确定、可复现。
package interchange

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/lechandonga/validator-slashing-guard-go/internal/domain"
	"github.com/lechandonga/validator-slashing-guard-go/internal/store"
)

// FormatVersion 是支持的 interchange_format_version（EIP-3076 通用版本 5）。
const FormatVersion = "5"

// SignedAttestation 是互导文件中的证明条目。
type SignedAttestation struct {
	SourceEpoch     uint64 `json:"source_epoch"`
	TargetEpoch     uint64 `json:"target_epoch"`
	SigningRootHex  string `json:"signing_root,omitempty"`
	BeaconBlockRoot string `json:"beacon_block_root,omitempty"`
}

// SignedBlock 是互导文件中的区块条目。
type SignedBlock struct {
	Slot uint64 `json:"slot"`
}

// ValidatorEntry 是单个验证者的条目集合。
type ValidatorEntry struct {
	PublicKey          string              `json:"pubkey"`
	SignedAttestations []SignedAttestation `json:"signed_attestations"`
	SignedBlocks       []SignedBlock       `json:"signed_blocks"`
}

// Metadata 对应 EIP-3076 metadata。
type Metadata struct {
	InterchangeFormatVersion string `json:"interchange_format_version"`
	GenesisValidatorsRoot    string `json:"genesis_validators_root"`
}

// File 是互导文件顶层结构。
type File struct {
	Metadata Metadata         `json:"metadata"`
	Data     []ValidatorEntry `json:"data"`
}

func decodeHex(s, name string) ([]byte, error) {
	if len(s) == 0 {
		return nil, nil
	}
	if len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		s = s[2:]
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("field %s: %w", name, err)
	}
	return b, nil
}

func encodeHex(b []byte) string {
	if b == nil {
		return ""
	}
	return "0x" + hex.EncodeToString(b)
}

// Parse 严格解析并校验互导文件：整体成功或整体失败。
func Parse(raw, expectedGenesisValidatorsRoot []byte) (*File, error) {
	var f File
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&f); err != nil {
		return nil, domain.GuardErrorf(domain.ReasonImportInvalid, "unparseable JSON: %v", err)
	}
	if dec.More() {
		return nil, domain.GuardErrorf(domain.ReasonImportInvalid, "trailing data after JSON document")
	}
	if f.Metadata.InterchangeFormatVersion != FormatVersion {
		return nil, domain.GuardErrorf(domain.ReasonImportInvalid,
			"unsupported interchange_format_version %q (supported: %s)",
			f.Metadata.InterchangeFormatVersion, FormatVersion)
	}
	gvr, err := decodeHex(f.Metadata.GenesisValidatorsRoot, "genesis_validators_root")
	if err != nil {
		return nil, domain.GuardErrorf(domain.ReasonImportInvalid, "%v", err)
	}
	if len(gvr) == 0 {
		return nil, domain.GuardErrorf(domain.ReasonImportInvalid, "genesis_validators_root is required")
	}
	if !bytes.Equal(gvr, expectedGenesisValidatorsRoot) {
		return nil, domain.GuardErrorf(domain.ReasonImportInvalid,
			"genesis_validators_root does not match local chain")
	}
	if len(f.Data) == 0 {
		return nil, domain.GuardErrorf(domain.ReasonImportInvalid, "data section is empty")
	}
	for vi := range f.Data {
		v := &f.Data[vi]
		if _, err := decodeHex(v.PublicKey, "pubkey"); err != nil {
			return nil, domain.GuardErrorf(domain.ReasonImportInvalid, "data[%d].pubkey: %v", vi, err)
		}
		for ai, a := range v.SignedAttestations {
			if a.SourceEpoch > a.TargetEpoch {
				return nil, domain.GuardErrorf(domain.ReasonImportInvalid,
					"validator %d attestation %d: source > target", vi, ai)
			}
			if _, err := decodeHex(a.SigningRootHex, "signing_root"); err != nil {
				return nil, domain.GuardErrorf(domain.ReasonImportInvalid,
					"validator %d attestation %d: %v", vi, ai, err)
			}
			if _, err := decodeHex(a.BeaconBlockRoot, "beacon_block_root"); err != nil {
				return nil, domain.GuardErrorf(domain.ReasonImportInvalid,
					"validator %d attestation %d: %v", vi, ai, err)
			}
		}
	}
	return &f, nil
}

// Import 把互导文件安全合并进存储：解析、冲突检测、原子写入。
// pubkeyToIndex 把文件中的公钥映射到本地验证者索引。
func Import(st *store.Store, raw, genesisValidatorsRoot []byte,
	pubkeyToIndex map[string]uint64) (int, error) {

	f, err := Parse(raw, genesisValidatorsRoot)
	if err != nil {
		return 0, err
	}

	imported := 0
	err = st.Update(func(existingAtts []domain.AttestationRecord, existingBlocks []domain.BlockRecord) (
		[]domain.AttestationRecord, []domain.BlockRecord, error) {

		atts := existingAtts
		blocks := existingBlocks

		for vi := range f.Data {
			v := &f.Data[vi]
			index, ok := pubkeyToIndex[v.PublicKey]
			if !ok {
				return nil, nil, domain.GuardErrorf(domain.ReasonImportInvalid,
					"unknown validator pubkey %s", v.PublicKey)
			}

			for _, a := range v.SignedAttestations {
				signingRoot, _ := decodeHex(a.SigningRootHex, "signing_root")
				blockRoot, _ := decodeHex(a.BeaconBlockRoot, "beacon_block_root")
				if len(signingRoot) == 0 {
					signingRoot = syntheticAttRoot(index, a.SourceEpoch, a.TargetEpoch, blockRoot)
				}
				if existing, reason := attConflict(index, a.SourceEpoch, a.TargetEpoch,
					blockRoot, signingRoot, atts); reason != "" {
					_ = existing
					if reason == "duplicate" {
						continue
					}
					return nil, nil, domain.GuardErrorf(domain.ReasonImportConflict,
						"validator %d attestation source=%d target=%d conflicts: %s",
						index, a.SourceEpoch, a.TargetEpoch, conflictText(reason))
				}
				atts = append(atts, domain.AttestationRecord{
					ValidatorIndex:  index,
					SourceEpoch:     a.SourceEpoch,
					TargetEpoch:     a.TargetEpoch,
					SigningRoot:     signingRoot,
					BeaconBlockRoot: blockRoot,
				})
				imported++
			}

			for _, b := range v.SignedBlocks {
				dup := false
				for _, eb := range blocks {
					if eb.ValidatorIndex == index && eb.Slot == b.Slot {
						dup = true
						break
					}
				}
				if dup {
					continue
				}
				blocks = append(blocks, domain.BlockRecord{
					ValidatorIndex: index,
					Slot:           b.Slot,
					SigningRoot:    syntheticBlockRoot(index, b.Slot),
				})
				imported++
			}
		}
		return atts, blocks, nil
	})
	if err != nil {
		return 0, err
	}
	return imported, nil
}

// Export 把当前记录导出为 EIP-3076 文件（按验证者分组）。
func Export(st *store.Store, genesisValidatorsRoot []byte,
	indexToPubkey map[uint64]string) ([]byte, error) {

	atts, blocks := st.Snapshot()
	byKey := map[string]*ValidatorEntry{}
	order := []string{}
	entry := func(index uint64) *ValidatorEntry {
		pk, ok := indexToPubkey[index]
		if !ok {
			pk = encodeHex(syntheticPubkey(index))
		}
		e, ok := byKey[pk]
		if !ok {
			e = &ValidatorEntry{PublicKey: pk}
			byKey[pk] = e
			order = append(order, pk)
		}
		return e
	}
	for _, a := range atts {
		e := entry(a.ValidatorIndex)
		e.SignedAttestations = append(e.SignedAttestations, SignedAttestation{
			SourceEpoch:     a.SourceEpoch,
			TargetEpoch:     a.TargetEpoch,
			SigningRootHex:  encodeHex(a.SigningRoot),
			BeaconBlockRoot: encodeHex(a.BeaconBlockRoot),
		})
	}
	for _, b := range blocks {
		e := entry(b.ValidatorIndex)
		e.SignedBlocks = append(e.SignedBlocks, SignedBlock{Slot: b.Slot})
	}
	f := File{
		Metadata: Metadata{
			InterchangeFormatVersion: FormatVersion,
			GenesisValidatorsRoot:    encodeHex(genesisValidatorsRoot),
		},
	}
	for _, pk := range order {
		f.Data = append(f.Data, *byKey[pk])
	}
	return json.MarshalIndent(&f, "", "  ")
}

// ExportToFile / ImportFromFile 是文件级便捷封装。
func ExportToFile(path string, st *store.Store, genesisValidatorsRoot []byte,
	indexToPubkey map[uint64]string) error {
	data, err := Export(st, genesisValidatorsRoot, indexToPubkey)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func ImportFromFile(st *store.Store, path string, genesisValidatorsRoot []byte,
	pubkeyToIndex map[string]uint64) (int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, domain.GuardErrorf(domain.ReasonImportInvalid, "cannot read %s: %v", path, err)
	}
	return Import(st, raw, genesisValidatorsRoot, pubkeyToIndex)
}

// attConflict 与 guard.FindAttestationConflict 规则一致；"duplicate" 表示幂等重复。
func attConflict(validatorIndex, source, target uint64, blockRoot, signingRoot []byte,
	atts []domain.AttestationRecord) (*domain.AttestationRecord, string) {

	var double *domain.AttestationRecord
	var surround *domain.AttestationRecord
	for i := range atts {
		old := &atts[i]
		if old.ValidatorIndex != validatorIndex {
			continue
		}
		if old.SourceEpoch == source && old.TargetEpoch == target &&
			bytes.Equal(old.BeaconBlockRoot, blockRoot) {
			return old, "duplicate"
		}
		if old.TargetEpoch == target && !bytes.Equal(old.BeaconBlockRoot, blockRoot) {
			double = old
		}
		if old.SourceEpoch < source && old.TargetEpoch > target {
			surround = old
		}
	}
	if double != nil {
		return double, domain.ReasonDoubleVote
	}
	if surround != nil {
		return surround, domain.ReasonSurroundVote
	}
	return nil, ""
}

func conflictText(reason string) string {
	switch reason {
	case domain.ReasonDoubleVote:
		return "double vote at same target epoch"
	case domain.ReasonSurroundVote:
		return "surrounding attestation span"
	}
	return reason
}

// syntheticAttRoot 为缺少签名根的导入条目生成确定性占位根，保证导入可复现。
func syntheticAttRoot(index, source, target uint64, blockRoot []byte) []byte {
	w := sha256.New()
	w.Write([]byte("import/att/v1"))
	w.Write(u64b(index))
	w.Write(u64b(source))
	w.Write(u64b(target))
	w.Write(blockRoot)
	return w.Sum(nil)
}

func syntheticBlockRoot(index, slot uint64) []byte {
	w := sha256.New()
	w.Write([]byte("import/block/v1"))
	w.Write(u64b(index))
	w.Write(u64b(slot))
	return w.Sum(nil)
}

func syntheticPubkey(index uint64) []byte {
	w := sha256.New()
	w.Write([]byte("local/pubkey"))
	w.Write(u64b(index))
	return w.Sum(nil)
}

func u64b(v uint64) []byte {
	b := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		b[i] = byte(v)
		v >>= 8
	}
	return b
}
