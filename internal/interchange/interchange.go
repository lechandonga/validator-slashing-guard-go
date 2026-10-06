// Package interchange 实现 EIP-3076（Slashing Protection Interchange Format）
// 标准防罚没记录互导，线格式严格遵循规范：
//
//   - metadata.interchange_format_version 为字符串 "5"；
//   - slot / source_epoch / target_epoch 一律是 JSON 十进制字符串（规范出于
//     跨语言整数精度考虑明确要求字符串）；
//   - 所有字节量（pubkey、genesis_validators_root、signing_root、
//     beacon_block_root）一律为带 0x 前缀的十六进制字符串；
//   - 区块条目必带 slot，signing_root 可选（完整数据库导出必须带）；
//   - 证明条目必带 source_epoch / target_epoch；signing_root、
//     beacon_block_root 可选；
//   - signed_blocks / signed_attestations 键本身可省略（为空）。
//
// 合并语义（导入，全有或全无的事务）：
//   - 文件必须整体可解析并通过结构校验，任何错误整体拒绝，不写入任何记录；
//   - 冲突判定以“是不是同一次签署内容”（signing_root）为准；
//   - 判定所需信息缺失、无法确定是否同一次签署时，以 IMPORT_AMBIGUOUS
//     整体拒绝并说明原因，绝不静默丢弃条目，也绝不部分写入；
//   - 同一文件重复导入幂等：完全相同的签署只计一次；
//   - 多验证者条目按身份（pubkey -> 本地身份）分别合并，互不串用；
//   - 导入与签名共用存储级临界区，并发下结论确定、可复现。
package interchange

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/lechandonga/validator-slashing-guard-go/internal/domain"
	"github.com/lechandonga/validator-slashing-guard-go/internal/store"
)

// FormatVersion 是 EIP-3076 通用线格式版本（"complete" database，版本 5）。
const FormatVersion = "5"

// BLSPubkeyLength 是规范规定的 BLS 公钥长度（字节）。
const BLSPubkeyLength = 48

// RootLength 是规范中 32 字节根的长度（字节）。
const RootLength = 32

// Epoch 按 EIP-3076 线格式编码为 JSON 十进制字符串。
type Epoch uint64

// Slot 按 EIP-3076 线格式编码为 JSON 十进制字符串。
type Slot uint64

func (e Epoch) MarshalJSON() ([]byte, error) {
	return json.Marshal(strconv.FormatUint(uint64(e), 10))
}

func (e *Epoch) UnmarshalJSON(data []byte) error {
	v, err := decodeUintString("epoch", data)
	if err != nil {
		return err
	}
	*e = Epoch(v)
	return nil
}

func (s Slot) MarshalJSON() ([]byte, error) {
	return json.Marshal(strconv.FormatUint(uint64(s), 10))
}

func (s *Slot) UnmarshalJSON(data []byte) error {
	v, err := decodeUintString("slot", data)
	if err != nil {
		return err
	}
	*s = Slot(v)
	return nil
}

func decodeUintString(kind string, data []byte) (uint64, error) {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return 0, fmt.Errorf("%s must be a JSON string per EIP-3076 wire format, got %s",
			kind, strings.TrimSpace(string(data)))
	}
	v, err := strconv.ParseUint(str, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q: %v", kind, str, err)
	}
	return v, nil
}

// SignedAttestation 是互导文件中的证明条目（字段名与规范逐字一致）。
type SignedAttestation struct {
	SourceEpoch     Epoch `json:"source_epoch"`
	TargetEpoch     Epoch `json:"target_epoch"`
	SigningRoot     Hex32 `json:"signing_root,omitempty"`
	BeaconBlockRoot Hex32 `json:"beacon_block_root,omitempty"`
}

// SignedBlock 是互导文件中的区块条目（字段名与规范逐字一致）。
type SignedBlock struct {
	Slot        Slot  `json:"slot"`
	SigningRoot Hex32 `json:"signing_root,omitempty"`
}

// ValidatorEntry 是单个验证者的条目集合。
type ValidatorEntry struct {
	PublicKey          HexBytes            `json:"pubkey"`
	SignedAttestations []SignedAttestation `json:"signed_attestations,omitempty"`
	SignedBlocks       []SignedBlock       `json:"signed_blocks,omitempty"`
}

// Metadata 对应 EIP-3076 metadata（版本号规范规定为字符串）。
type Metadata struct {
	InterchangeFormatVersion string   `json:"interchange_format_version"`
	GenesisValidatorsRoot    HexBytes `json:"genesis_validators_root"`
}

// File 是互导文件顶层结构。
type File struct {
	Metadata Metadata         `json:"metadata"`
	Data     []ValidatorEntry `json:"data"`
}

// HexBytes 是带 0x 前缀的十六进制字节量；长度由解析阶段按字段校验。
type HexBytes []byte

func (h HexBytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(encodeHex([]byte(h)))
}

func (h *HexBytes) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return fmt.Errorf("hex field must be a 0x-prefixed string")
	}
	b, err := decodeHex(str)
	if err != nil {
		return err
	}
	*h = b
	return nil
}

// Hex32 是规范中 32 字节根的线格式类型。
type Hex32 []byte

func (h Hex32) MarshalJSON() ([]byte, error) {
	return json.Marshal(encodeHex([]byte(h)))
}

func (h *Hex32) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return fmt.Errorf("root field must be a 0x-prefixed string")
	}
	b, err := decodeHex(str)
	if err != nil {
		return err
	}
	if len(b) != RootLength {
		return fmt.Errorf("root must be %d bytes, got %d", RootLength, len(b))
	}
	*h = b
	return nil
}

func decodeHex(s string) ([]byte, error) {
	if len(s) < 2 || s[0] != '0' || (s[1] != 'x' && s[1] != 'X') {
		return nil, fmt.Errorf("hex value %q is missing the 0x prefix", s)
	}
	b, err := hex.DecodeString(s[2:])
	if err != nil {
		return nil, fmt.Errorf("invalid hex %q: %v", s, err)
	}
	return b, nil
}

func encodeHex(b []byte) string { return "0x" + hex.EncodeToString(b) }

// Parse 严格按 EIP-3076 解析并校验互导文件：整体成功或整体失败。
// 结构/类型/长度/值域非法一律 IMPORT_INVALID；不做任何存储修改。
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
			"unsupported interchange_format_version %q (supported: %q)",
			f.Metadata.InterchangeFormatVersion, FormatVersion)
	}
	if len(f.Metadata.GenesisValidatorsRoot) == 0 {
		return nil, domain.GuardErrorf(domain.ReasonImportInvalid,
			"metadata.genesis_validators_root is required")
	}
	if !bytes.Equal(f.Metadata.GenesisValidatorsRoot, expectedGenesisValidatorsRoot) {
		return nil, domain.GuardErrorf(domain.ReasonImportInvalid,
			"genesis_validators_root does not match local chain")
	}
	if len(f.Data) == 0 {
		return nil, domain.GuardErrorf(domain.ReasonImportInvalid, "data section is empty")
	}

	seenPubkeys := map[string]bool{}
	for vi := range f.Data {
		v := &f.Data[vi]
		if len(v.PublicKey) != BLSPubkeyLength {
			return nil, domain.GuardErrorf(domain.ReasonImportInvalid,
				"data[%d].pubkey must be %d bytes, got %d", vi, BLSPubkeyLength, len(v.PublicKey))
		}
		key := encodeHex(v.PublicKey)
		if seenPubkeys[key] {
			return nil, domain.GuardErrorf(domain.ReasonImportInvalid,
				"data[%d].pubkey %s appears more than once", vi, key)
		}
		seenPubkeys[key] = true

		for ai, a := range v.SignedAttestations {
			if a.SourceEpoch > a.TargetEpoch {
				return nil, domain.GuardErrorf(domain.ReasonImportInvalid,
					"validator %s attestation %d: source_epoch %d > target_epoch %d",
					key, ai, a.SourceEpoch, a.TargetEpoch)
			}
		}
	}
	return &f, nil
}

// ValidatorDirectory 提供互导身份与本地托管身份之间的映射。
// guard.Client 实现该接口。
type ValidatorDirectory interface {
	// ValidatorIndexByPubkey 返回本地托管的验证者索引；身份本地不存在时 ok=false。
	ValidatorIndexByPubkey(pubkey []byte) (index uint64, ok bool)
	// PubkeyByValidatorIndex 返回该本地验证者的规范公钥；身份不存在时 ok=false。
	PubkeyByValidatorIndex(index uint64) (pubkey []byte, ok bool)
	// HostedValidators 返回本地托管的全部验证者索引（导出用，调用方据此排序）。
	HostedValidators() []uint64
}

// ImportOptions 控制导入时的身份处理语义。
type ImportOptions struct {
	// SkipUnknownValidators 为 true 时，文件中本地未托管的验证者条目被
	// 整体跳过（该身份一条都不合并，也不报错）；为 false（默认）时，
	// 出现未知身份整体拒绝（UNKNOWN_VALIDATOR），绝不部分导入。
	SkipUnknownValidators bool
}

// rootCmp 是依据 signing_root 对“是否同一次签署”的三值判定。
type rootCmp int

const (
	rootSame      rootCmp = iota // 两侧根都在且相等：同一次签署
	rootDifferent                // 两侧根都在且不等：罚没冲突
	rootUnknown                  // 至少一侧缺根：无法确定，必须保守拒绝
)

func classifyRoots(existing, incoming []byte) rootCmp {
	if len(existing) == 0 || len(incoming) == 0 {
		return rootUnknown
	}
	if bytes.Equal(existing, incoming) {
		return rootSame
	}
	return rootDifferent
}

// Import 把标准 EIP-3076 文件安全合并进存储。
// 返回新写入（此前不存在）的记录条数；冲突/歧义/格式错误时返回 0 与错误，
// 且存储保持调用前状态（全有或全无）。
func Import(st *store.Store, raw, genesisValidatorsRoot []byte,
	dir ValidatorDirectory, opts *ImportOptions) (int, error) {

	f, err := Parse(raw, genesisValidatorsRoot)
	if err != nil {
		return 0, err
	}
	skipUnknown := opts != nil && opts.SkipUnknownValidators

	imported := 0
	err = st.Update(func(existingAtts []domain.AttestationRecord, existingBlocks []domain.BlockRecord) (
		[]domain.AttestationRecord, []domain.BlockRecord, error) {

		atts := existingAtts
		blocks := existingBlocks

		for vi := range f.Data {
			v := &f.Data[vi]
			index, known := dir.ValidatorIndexByPubkey(v.PublicKey)
			if !known {
				if skipUnknown {
					continue
				}
				return nil, nil, domain.GuardErrorf(domain.ReasonUnknownValidator,
					"interchange contains validator %s which is not hosted locally; "+
						"host the identity first or enable explicit skip-unknown semantics",
					encodeHex(v.PublicKey))
			}

			// ---- 区块：按 (身份, slot) 判定是否同一次签署 ----
			for _, b := range v.SignedBlocks {
				incomingRoot := append([]byte(nil), b.SigningRoot...)
				matched := false
				for bi := range blocks {
					eb := &blocks[bi]
					if eb.ValidatorIndex != index || eb.Slot != uint64(b.Slot) {
						continue
					}
					matched = true
					switch classifyRoots(eb.SigningRoot, incomingRoot) {
					case rootSame:
						// 同一次签署：幂等，不重复计数。
					case rootDifferent:
						return nil, nil, domain.GuardErrorf(domain.ReasonImportConflict,
							"validator %d signed two different blocks at slot %d",
							index, b.Slot)
					case rootUnknown:
						return nil, nil, domain.GuardErrorf(domain.ReasonImportAmbiguous,
							"cannot determine whether incoming block at slot %d is the same "+
								"signing as an existing record for validator %d: signing_root "+
								"missing on one side; refusing to guess", b.Slot, index)
					}
				}
				if matched {
					continue
				}
				blocks = append(blocks, domain.BlockRecord{
					ValidatorIndex: index,
					Slot:           uint64(b.Slot),
					SigningRoot:    incomingRoot,
				})
				imported++
			}

			// ---- 证明：同 target 按 signing_root 判定；区间做双向 surround 检测 ----
			for _, a := range v.SignedAttestations {
				incoming := domain.AttestationRecord{
					ValidatorIndex:  index,
					SourceEpoch:     uint64(a.SourceEpoch),
					TargetEpoch:     uint64(a.TargetEpoch),
					SigningRoot:     append([]byte(nil), a.SigningRoot...),
					BeaconBlockRoot: append([]byte(nil), a.BeaconBlockRoot...),
				}
				// 工作集同时包含库内既有条目与本文件已并入的条目，因此
				// “与库冲突”和“文件内自相矛盾”用同一套规则整体拒绝。
				sameContent, reason, amsg := attPair(index, incoming, atts, true)
				if reason != "" {
					return nil, nil, pairError(reason, amsg)
				}
				if !sameContent {
					atts = append(atts, incoming)
					imported++
				}
			}
		}
		return atts, blocks, nil
	})
	if err != nil {
		return 0, err
	}
	return imported, nil
}

func pairError(reason, msg string) error {
	switch reason {
	case domain.ReasonImportAmbiguous:
		return domain.GuardErrorf(domain.ReasonImportAmbiguous, "%s", msg)
	default:
		return domain.GuardErrorf(domain.ReasonImportConflict, "%s", msg)
	}
}

// Export 把本地托管身份的全部记录导出为规范 EIP-3076 文件。
// 导出在存储的一致性快照上完成：与并发签署交错时，结果要么包含某次签署、
// 要么不包含，绝不会导出半条记录。区块条目携带 signing_root（完整数据库语义），
// 使对方工具能够判断同一 slot 是否签过不同区块。
func Export(st *store.Store, genesisValidatorsRoot []byte, dir ValidatorDirectory) ([]byte, error) {
	atts, blocks := st.Snapshot()

	indices := dir.HostedValidators()
	sort.Slice(indices, func(i, j int) bool { return indices[i] < indices[j] })

	attByIndex := map[uint64][]domain.AttestationRecord{}
	blockByIndex := map[uint64][]domain.BlockRecord{}
	for _, a := range atts {
		attByIndex[a.ValidatorIndex] = append(attByIndex[a.ValidatorIndex], a)
	}
	for _, b := range blocks {
		blockByIndex[b.ValidatorIndex] = append(blockByIndex[b.ValidatorIndex], b)
	}

	f := File{
		Metadata: Metadata{
			InterchangeFormatVersion: FormatVersion,
			GenesisValidatorsRoot:    HexBytes(append([]byte(nil), genesisValidatorsRoot...)),
		},
	}
	for _, index := range indices {
		pubkey, ok := dir.PubkeyByValidatorIndex(index)
		if !ok {
			continue
		}
		entry := ValidatorEntry{PublicKey: HexBytes(append([]byte(nil), pubkey...))}

		ea := attByIndex[index]
		sort.Slice(ea, func(i, j int) bool {
			if ea[i].TargetEpoch != ea[j].TargetEpoch {
				return ea[i].TargetEpoch < ea[j].TargetEpoch
			}
			if ea[i].SourceEpoch != ea[j].SourceEpoch {
				return ea[i].SourceEpoch < ea[j].SourceEpoch
			}
			return bytes.Compare(ea[i].SigningRoot, ea[j].SigningRoot) < 0
		})
		for _, a := range ea {
			entry.SignedAttestations = append(entry.SignedAttestations, SignedAttestation{
				SourceEpoch:     Epoch(a.SourceEpoch),
				TargetEpoch:     Epoch(a.TargetEpoch),
				SigningRoot:     Hex32(append([]byte(nil), a.SigningRoot...)),
				BeaconBlockRoot: Hex32(append([]byte(nil), a.BeaconBlockRoot...)),
			})
		}

		eb := blockByIndex[index]
		sort.Slice(eb, func(i, j int) bool { return eb[i].Slot < eb[j].Slot })
		for _, b := range eb {
			entry.SignedBlocks = append(entry.SignedBlocks, SignedBlock{
				Slot:        Slot(b.Slot),
				SigningRoot: Hex32(append([]byte(nil), b.SigningRoot...)),
			})
		}
		// 没有任何记录的身份不产生条目，避免“空验证者”噪声；身份仍由
		// ValidatorDirectory 托管，后续一旦签署即会出现在导出中。
		if len(entry.SignedAttestations) == 0 && len(entry.SignedBlocks) == 0 {
			continue
		}
		f.Data = append(f.Data, entry)
	}
	return json.MarshalIndent(&f, "", "  ")
}

// ExportToFile / ImportFromFile 是文件级便捷封装。
func ExportToFile(path string, st *store.Store, genesisValidatorsRoot []byte,
	dir ValidatorDirectory) error {
	data, err := Export(st, genesisValidatorsRoot, dir)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func ImportFromFile(st *store.Store, path string, genesisValidatorsRoot []byte,
	dir ValidatorDirectory, opts *ImportOptions) (int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, domain.GuardErrorf(domain.ReasonImportInvalid, "cannot read %s: %v", path, err)
	}
	return Import(st, raw, genesisValidatorsRoot, dir, opts)
}

// attPair 在给定身份维度上把 incoming 与 atts 逐条比对。
// sameContent=true 表示找到同一次签署（幂等重复，可跳过）；
// reason 非空表示罚没冲突（IMPORT_CONFLICT）或无法判定（IMPORT_AMBIGUOUS）。
// allowRootFallback 为 true 时（仅导入），若 signing_root 两侧齐全则严格按
// 根判定；若两侧均缺根，退而使用 beacon_block_root + (source,target) 判定，
// 仍无法确定时返回 IMPORT_AMBIGUOUS，绝不猜测。
func attPair(validatorIndex uint64, incoming domain.AttestationRecord,
	atts []domain.AttestationRecord, allowRootFallback bool) (sameContent bool, reason, msg string) {

	for i := range atts {
		old := &atts[i]
		if old.ValidatorIndex != validatorIndex {
			continue
		}

		// 1) 完全相同的签署：signing_root 两侧齐全且相等。
		if len(old.SigningRoot) > 0 && len(incoming.SigningRoot) > 0 {
			if bytes.Equal(old.SigningRoot, incoming.SigningRoot) {
				return true, "", ""
			}
			// 同 target 且根不同 => double vote。
			if old.TargetEpoch == incoming.TargetEpoch {
				return false, domain.ReasonImportConflict, fmt.Sprintf(
					"validator %d signed two different attestations at target epoch %d",
					validatorIndex, incoming.TargetEpoch)
			}
		}

		// 2) surround（双向）：既罚 old 包 incoming，也罚 incoming 包 old。
		if old.SourceEpoch < incoming.SourceEpoch && old.TargetEpoch > incoming.TargetEpoch {
			return false, domain.ReasonImportConflict, fmt.Sprintf(
				"validator %d: incoming attestation span (%d,%d) is surrounded by "+
					"existing span (%d,%d)",
				validatorIndex, incoming.SourceEpoch, incoming.TargetEpoch,
				old.SourceEpoch, old.TargetEpoch)
		}
		if incoming.SourceEpoch < old.SourceEpoch && incoming.TargetEpoch > old.TargetEpoch {
			return false, domain.ReasonImportConflict, fmt.Sprintf(
				"validator %d: incoming attestation span (%d,%d) surrounds an existing "+
					"span (%d,%d)",
				validatorIndex, incoming.SourceEpoch, incoming.TargetEpoch,
				old.SourceEpoch, old.TargetEpoch)
		}

		// 3) 同 target 的进一步判定只在两侧根不同时缺失或都缺失时才走到这里。
		if old.TargetEpoch != incoming.TargetEpoch {
			continue
		}
		if !allowRootFallback {
			continue
		}
		if len(old.BeaconBlockRoot) > 0 && len(incoming.BeaconBlockRoot) > 0 {
			if old.SourceEpoch == incoming.SourceEpoch &&
				bytes.Equal(old.BeaconBlockRoot, incoming.BeaconBlockRoot) {
				// 两侧都缺 signing_root，但最小内容集完全一致：同一次签署。
				return true, "", ""
			}
			// 内容不同（投票根不同或 source 不同）：double vote。
			return false, domain.ReasonImportConflict, fmt.Sprintf(
				"validator %d signed two different attestations at target epoch %d "+
					"(signing_root absent; distinguished by beacon_block_root)",
				validatorIndex, incoming.TargetEpoch)
		}
		// 同 target 但至少一侧缺 signing_root 且无法用投票根判定：保守拒绝。
		return false, domain.ReasonImportAmbiguous, fmt.Sprintf(
			"cannot determine whether incoming attestation (source=%d target=%d) for "+
				"validator %d is the same signing as an existing record at the same "+
				"target epoch: signing_root/beacon_block_root insufficient; refusing to guess",
			incoming.SourceEpoch, incoming.TargetEpoch, validatorIndex)
	}
	return false, "", ""
}
