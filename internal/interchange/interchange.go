// Package interchange 实现 EIP-3076（interchange_format_version = "5"）
// 防罚没记录互导。
//
// 线格式严格遵循规范：
//   - 所有 slot / epoch 均为“引号包裹的十进制字符串”（规范 Rationale:
//     Integer Representation），不接受 JSON 数字；
//   - signed_attestations 条目仅含 source_epoch、target_epoch（必填）与
//     signing_root（可选）；signed_blocks 条目仅含 slot（必填）与
//     signing_root（可选）；不存在任何本地自创字段；
//   - pubkey 为 0x 前缀的 48 字节 BLS 公钥，genesis_validators_root 为
//     0x 前缀的 32 字节根。
//
// 导入语义（全有或全无）：
//   - 文件整体解析、逐条目校验、冲突检测全部完成前不写任何记录；
//   - 缺少 signing_root 的条目内部记为 domain.DummySigningRoot（规范建议的
//     0x0 占位），同 slot / 同 target 的新内容无法证明为“同一次签署”，
//     一律保守判定为冲突，整体拒绝；
//   - 同一文件重复导入幂等（含缺 signing_root 的条目，按其业务键去重）；
//   - 文件中的身份本地不存在时默认整体拒绝（IMPORT_UNKNOWN_VALIDATOR），
//     也可通过 SkipUnknownValidators 显式选择稳定的“跳过并计数”语义。
package interchange

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"

	"github.com/lechandonga/validator-slashing-guard-go/internal/domain"
	"github.com/lechandonga/validator-slashing-guard-go/internal/store"
)

// FormatVersion 是支持的 interchange_format_version（EIP-3076 通用版本 5）。
const FormatVersion = "5"

// uint64String 是规范要求的“引号十进制整数”。
type uint64String uint64

func (u *uint64String) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || b[0] != '"' {
		return fmt.Errorf("must be a quoted decimal string, got %s", string(b))
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	if !isCanonicalDecimal(s) {
		return fmt.Errorf("not a canonical non-negative decimal integer: %q", s)
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return err
	}
	*u = uint64String(v)
	return nil
}

func (u uint64String) MarshalJSON() ([]byte, error) {
	return json.Marshal(strconv.FormatUint(uint64(u), 10))
}

func isCanonicalDecimal(s string) bool {
	if s == "" {
		return false
	}
	if len(s) > 1 && s[0] == '0' {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// hexBytes 是规范的 0x 前缀十六进制字符串（长度严格校验）。
type hexBytes []byte

func (h *hexBytes) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	decoded, err := decodeHex(s)
	if err != nil {
		return err
	}
	*h = decoded
	return nil
}

func (h hexBytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(encodeHex([]byte(h)))
}

// SignedAttestation 是互导文件中的证明条目（字段以 EIP-3076 为准）。
type SignedAttestation struct {
	SourceEpoch uint64String `json:"source_epoch"`
	TargetEpoch uint64String `json:"target_epoch"`
	SigningRoot hexBytes     `json:"signing_root,omitempty"`
}

// SignedBlock 是互导文件中的区块条目（字段以 EIP-3076 为准）。
type SignedBlock struct {
	Slot        *uint64String `json:"slot"`
	SigningRoot hexBytes      `json:"signing_root,omitempty"`
}

// ValidatorEntry 是单个验证者的条目集合。
// signed_blocks 与 signed_attestations 在规范中均为必填键（可为空数组）。
type ValidatorEntry struct {
	PublicKey          hexBytes            `json:"pubkey"`
	SignedBlocks       []SignedBlock       `json:"signed_blocks"`
	SignedAttestations []SignedAttestation `json:"signed_attestations"`
}

// Metadata 对应 EIP-3076 metadata。
type Metadata struct {
	InterchangeFormatVersion string   `json:"interchange_format_version"`
	GenesisValidatorsRoot    hexBytes `json:"genesis_validators_root"`
}

// File 是互导文件顶层结构。
type File struct {
	Metadata Metadata         `json:"metadata"`
	Data     []ValidatorEntry `json:"data"`
}

// Options 控制导入行为。
type Options struct {
	// PubkeyToIndex 把文件中的 BLS 公钥映射到本地验证者索引。
	PubkeyToIndex map[string]uint64
	// SkipUnknownValidators 为 true 时，文件中本地不存在的身份被稳定跳过
	// （跳过数在 Result.SkippedValidators 中返回）；为 false（默认）时
	// 整体拒绝，原因 UNKNOWN_VALIDATOR。
	SkipUnknownValidators bool
}

// Result 是导入结论。
type Result struct {
	Imported            int // 新并入的记录数（去重后）
	Duplicate           int // 幂等命中的既有条目数
	SkippedValidators   int // 因身份本地不存在而跳过的验证者条目数
	SkippedAttestations int
	SkippedBlocks       int
}

func decodeHex(s string) ([]byte, error) {
	if len(s) < 2 || s[0] != '0' || (s[1] != 'x' && s[1] != 'X') {
		return nil, fmt.Errorf("hex string must be 0x-prefixed: %q", s)
	}
	b, err := hex.DecodeString(s[2:])
	if err != nil {
		return nil, fmt.Errorf("invalid hex %q: %w", s, err)
	}
	return b, nil
}

func encodeHex(b []byte) string {
	return "0x" + hex.EncodeToString(b)
}

// Parse 严格解析并校验互导文件：整体成功或整体失败。
func Parse(raw, expectedGenesisValidatorsRoot []byte) (*File, error) {
	var f File
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
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
	if len(f.Metadata.GenesisValidatorsRoot) != 32 {
		return nil, domain.GuardErrorf(domain.ReasonImportInvalid,
			"genesis_validators_root must be 32 bytes, got %d", len(f.Metadata.GenesisValidatorsRoot))
	}
	if !bytes.Equal(f.Metadata.GenesisValidatorsRoot, expectedGenesisValidatorsRoot) {
		return nil, domain.GuardErrorf(domain.ReasonImportInvalid,
			"genesis_validators_root does not match local chain")
	}
	if f.Data == nil {
		return nil, domain.GuardErrorf(domain.ReasonImportInvalid, "data section is required")
	}
	seenPub := map[string]bool{}
	for vi := range f.Data {
		v := &f.Data[vi]
		if len(v.PublicKey) != 48 {
			return nil, domain.GuardErrorf(domain.ReasonImportInvalid,
				"data[%d].pubkey must be 48 bytes, got %d", vi, len(v.PublicKey))
		}
		pkHex := encodeHex(v.PublicKey)
		if seenPub[pkHex] {
			return nil, domain.GuardErrorf(domain.ReasonImportInvalid,
				"data[%d]: duplicate validator entry for pubkey %s", vi, pkHex)
		}
		seenPub[pkHex] = true
		if v.SignedBlocks == nil || v.SignedAttestations == nil {
			return nil, domain.GuardErrorf(domain.ReasonImportInvalid,
				"data[%d]: signed_blocks and signed_attestations are required keys", vi)
		}
		for bi, b := range v.SignedBlocks {
			if b.Slot == nil {
				return nil, domain.GuardErrorf(domain.ReasonImportInvalid,
					"validator %d block %d: slot is required", vi, bi)
			}
			if len(b.SigningRoot) != 0 && len(b.SigningRoot) != 32 {
				return nil, domain.GuardErrorf(domain.ReasonImportInvalid,
					"validator %d block %d: signing_root must be 32 bytes", vi, bi)
			}
		}
		for ai, a := range v.SignedAttestations {
			if uint64(a.SourceEpoch) > uint64(a.TargetEpoch) {
				return nil, domain.GuardErrorf(domain.ReasonImportInvalid,
					"validator %d attestation %d: source_epoch > target_epoch", vi, ai)
			}
			if len(a.SigningRoot) != 0 && len(a.SigningRoot) != 32 {
				return nil, domain.GuardErrorf(domain.ReasonImportInvalid,
					"validator %d attestation %d: signing_root must be 32 bytes", vi, ai)
			}
		}
	}
	return &f, nil
}

// Import 把互导文件安全合并进存储：解析、身份解析、冲突检测全部完成后
// 才整体原子写入。返回错误时记录集合保持导入前状态。
func Import(st *store.Store, raw, genesisValidatorsRoot []byte, opts Options) (Result, error) {
	f, err := Parse(raw, genesisValidatorsRoot)
	if err != nil {
		return Result{}, err
	}

	res := Result{}
	err = st.Update(func(existingAtts []domain.AttestationRecord, existingBlocks []domain.BlockRecord) (
		[]domain.AttestationRecord, []domain.BlockRecord, error) {

		atts := existingAtts
		blocks := existingBlocks

		// 第一阶段：解析身份、构造待合并条目，同时完成文件内部自冲突/重复检测。
		var pendingAtts []domain.AttestationRecord
		var pendingBlocks []domain.BlockRecord

		for vi := range f.Data {
			v := &f.Data[vi]
			pkHex := encodeHex(v.PublicKey)
			index, known := opts.PubkeyToIndex[pkHex]
			if !known {
				if !opts.SkipUnknownValidators {
					return nil, nil, domain.GuardErrorf(domain.ReasonUnknownValidator,
						"interchange contains unknown validator pubkey %s (no local identity)", pkHex)
				}
				res.SkippedValidators++
				res.SkippedAttestations += len(v.SignedAttestations)
				res.SkippedBlocks += len(v.SignedBlocks)
				continue
			}

			for ai, a := range v.SignedAttestations {
				src, tgt := uint64(a.SourceEpoch), uint64(a.TargetEpoch)
				root := []byte(a.SigningRoot)
				if len(root) == 0 {
					root = append([]byte(nil), domain.DummySigningRoot...)
				}
				rec := domain.AttestationRecord{
					ValidatorIndex: index,
					SourceEpoch:    src,
					TargetEpoch:    tgt,
					SigningRoot:    root,
				}
				if err := checkAttSelfContained(index, uint64(vi), uint64(ai), rec, pendingAtts); err != nil {
					return nil, nil, err
				}
				pendingAtts = append(pendingAtts, rec)
			}

			for bi, b := range v.SignedBlocks {
				slot := uint64(*b.Slot)
				root := []byte(b.SigningRoot)
				if len(root) == 0 {
					root = append([]byte(nil), domain.DummySigningRoot...)
				}
				rec := domain.BlockRecord{
					ValidatorIndex: index,
					Slot:           slot,
					SigningRoot:    root,
				}
				if err := checkBlockSelfContained(index, uint64(vi), uint64(bi), rec, pendingBlocks); err != nil {
					return nil, nil, err
				}
				pendingBlocks = append(pendingBlocks, rec)
			}
		}

		// 第二阶段：与既有记录逐条合并。判定基于“是否同一次签署内容”：
		// 双方签名根都是真实根且相等 => 同一次签署（幂等）；
		// 否则按防罚没规则冲突，整体拒绝。
		for _, r := range pendingAtts {
			switch classifyAttestation(r, atts) {
			case mergeDuplicate:
				res.Duplicate++
			case mergeConflict:
				return nil, nil, domain.GuardErrorf(domain.ReasonImportConflict,
					"validator %d attestation source=%d target=%d: %s",
					r.ValidatorIndex, r.SourceEpoch, r.TargetEpoch,
					attConflictText(r, atts))
			default:
				atts = append(atts, r)
				res.Imported++
			}
		}
		for _, r := range pendingBlocks {
			switch classifyBlock(r, blocks) {
			case mergeDuplicate:
				res.Duplicate++
			case mergeConflict:
				return nil, nil, domain.GuardErrorf(domain.ReasonImportConflict,
					"validator %d block slot=%d: %s",
					r.ValidatorIndex, r.Slot, blockConflictText(r, blocks))
			default:
				blocks = append(blocks, r)
				res.Imported++
			}
		}
		return atts, blocks, nil
	})
	if err != nil {
		return Result{}, err
	}
	return res, nil
}

type mergeClass int

const (
	mergeNew mergeClass = iota
	mergeDuplicate
	mergeConflict
)

// checkAttSelfContained 检测同一文件内部的证明重复/冲突。
// 缺签名根的条目按业务键 (index,source,target) 判幂等；同 target 不同内容、
// surround 区间一律冲突；无法确定是否同一次签署（缺根）时整体拒绝。
func checkAttSelfContained(index, vi, ai uint64, rec domain.AttestationRecord, pending []domain.AttestationRecord) error {
	for _, p := range pending {
		o := p
		if o.ValidatorIndex != index {
			continue
		}
		if bothRoots(rec.SigningRoot, o.SigningRoot) && bytes.Equal(rec.SigningRoot, o.SigningRoot) {
			return nil // 同一次签署，重复
		}
		if o.TargetEpoch == rec.TargetEpoch {
			// 至少一方缺根，或根不同。
			sameKey := !domain.HasSigningRoot(rec.SigningRoot) &&
				!domain.HasSigningRoot(o.SigningRoot) &&
				o.SourceEpoch == rec.SourceEpoch
			if sameKey {
				return nil // 无根条目业务键完全一致 => 幂等重复
			}
			return domain.GuardErrorf(domain.ReasonImportConflict,
				"validator %d (data[%d]) attestation %d: double vote within import file at target epoch %d",
				index, vi, ai, rec.TargetEpoch)
		}
		if (o.SourceEpoch < rec.SourceEpoch && o.TargetEpoch > rec.TargetEpoch) ||
			(rec.SourceEpoch < o.SourceEpoch && rec.TargetEpoch > o.TargetEpoch) {
			return domain.GuardErrorf(domain.ReasonImportConflict,
				"validator %d (data[%d]) attestation %d: surrounding attestation spans within import file",
				index, vi, ai)
		}
	}
	return nil
}

// checkBlockSelfContained 检测同一文件内部的区块重复/冲突。
func checkBlockSelfContained(index, vi, bi uint64, rec domain.BlockRecord, pending []domain.BlockRecord) error {
	for _, p := range pending {
		o := p
		if o.ValidatorIndex != index {
			continue
		}
		if o.Slot != rec.Slot {
			continue
		}
		if bothRoots(rec.SigningRoot, o.SigningRoot) && bytes.Equal(rec.SigningRoot, o.SigningRoot) {
			return nil
		}
		if !domain.HasSigningRoot(rec.SigningRoot) && !domain.HasSigningRoot(o.SigningRoot) {
			return nil // 两个同 slot 无根条目视为同一条历史，幂等
		}
		return domain.GuardErrorf(domain.ReasonImportConflict,
			"validator %d (data[%d]) block %d: different blocks at same slot %d within import file",
			index, vi, bi, rec.Slot)
	}
	return nil
}

func bothRoots(a, b []byte) bool {
	return domain.HasSigningRoot(a) && domain.HasSigningRoot(b)
}

// classifyAttestation 对既有记录集合判定新条目的合并类别。
func classifyAttestation(r domain.AttestationRecord, atts []domain.AttestationRecord) mergeClass {
	duplicate := false
	for i := range atts {
		o := &atts[i]
		if o.ValidatorIndex != r.ValidatorIndex {
			continue
		}
		if bothRoots(r.SigningRoot, o.SigningRoot) && bytes.Equal(r.SigningRoot, o.SigningRoot) {
			duplicate = true
			continue
		}
		if o.TargetEpoch == r.TargetEpoch {
			sameKey := !domain.HasSigningRoot(r.SigningRoot) &&
				!domain.HasSigningRoot(o.SigningRoot) &&
				o.SourceEpoch == r.SourceEpoch
			if sameKey {
				duplicate = true
				continue
			}
			return mergeConflict // double vote：无法证明同一次签署
		}
		if (o.SourceEpoch < r.SourceEpoch && o.TargetEpoch > r.TargetEpoch) ||
			(r.SourceEpoch < o.SourceEpoch && r.TargetEpoch > o.TargetEpoch) {
			return mergeConflict // surround
		}
	}
	if duplicate {
		return mergeDuplicate
	}
	return mergeNew
}

// classifyBlock 对既有区块记录判定新条目的合并类别。
func classifyBlock(r domain.BlockRecord, blocks []domain.BlockRecord) mergeClass {
	duplicate := false
	for i := range blocks {
		o := &blocks[i]
		if o.ValidatorIndex != r.ValidatorIndex {
			continue
		}
		if bothRoots(r.SigningRoot, o.SigningRoot) && bytes.Equal(r.SigningRoot, o.SigningRoot) {
			duplicate = true
			continue
		}
		if o.Slot == r.Slot {
			if !domain.HasSigningRoot(r.SigningRoot) &&
				!domain.HasSigningRoot(o.SigningRoot) {
				duplicate = true
				continue
			}
			return mergeConflict // 同 slot 不同内容，或缺根无法确定
		}
	}
	if duplicate {
		return mergeDuplicate
	}
	return mergeNew
}

func attConflictText(r domain.AttestationRecord, atts []domain.AttestationRecord) string {
	for i := range atts {
		o := &atts[i]
		if o.ValidatorIndex != r.ValidatorIndex {
			continue
		}
		if o.TargetEpoch == r.TargetEpoch {
			if !domain.HasSigningRoot(r.SigningRoot) || !domain.HasSigningRoot(o.SigningRoot) {
				return "double vote at same target epoch (signing_root missing, cannot prove same signing)"
			}
			return "double vote at same target epoch (different signing_root)"
		}
		if (o.SourceEpoch < r.SourceEpoch && o.TargetEpoch > r.TargetEpoch) ||
			(r.SourceEpoch < o.SourceEpoch && r.TargetEpoch > o.TargetEpoch) {
			return "surrounding attestation spans"
		}
	}
	return "conflicts with existing attestation record"
}

func blockConflictText(r domain.BlockRecord, blocks []domain.BlockRecord) string {
	for i := range blocks {
		o := &blocks[i]
		if o.ValidatorIndex == r.ValidatorIndex && o.Slot == r.Slot {
			if !domain.HasSigningRoot(r.SigningRoot) || !domain.HasSigningRoot(o.SigningRoot) {
				return "different block at same slot (signing_root missing, cannot prove same signing)"
			}
			return "different signing_root at same slot"
		}
	}
	return "conflicts with existing block record"
}

// Export 把当前记录导出为 EIP-3076 文件。
// indexToPubkey 提供本地身份索引到 BLS 公钥的映射；记录均来自本地真实签署，
// signing_root 一定存在并原样导出（含区块条目，供对端判断同 slot 是否签过不同区块）。
// 导出在一次存储快照上完成：结果要么包含某条新签署、要么不包含，不会出现半条记录。
func Export(st *store.Store, genesisValidatorsRoot []byte,
	indexToPubkey map[uint64][]byte) ([]byte, error) {

	atts, blocks := st.Snapshot()

	if len(genesisValidatorsRoot) != 32 {
		return nil, domain.GuardErrorf(domain.ReasonImportInvalid,
			"genesis_validators_root must be 32 bytes, got %d", len(genesisValidatorsRoot))
	}

	byKey := map[string]*ValidatorEntry{}
	var order []string
	entry := func(index uint64) (*ValidatorEntry, error) {
		pk, ok := indexToPubkey[index]
		if !ok {
			return nil, domain.GuardErrorf(domain.ReasonUnknownValidator,
				"no export pubkey configured for local validator %d", index)
		}
		if len(pk) != 48 {
			return nil, domain.GuardErrorf(domain.ReasonImportInvalid,
				"export pubkey for validator %d must be 48 bytes, got %d", index, len(pk))
		}
		pkHex := encodeHex(pk)
		e, ok := byKey[pkHex]
		if !ok {
			e = &ValidatorEntry{PublicKey: append([]byte(nil), pk...),
				SignedBlocks: []SignedBlock{}, SignedAttestations: []SignedAttestation{}}
			byKey[pkHex] = e
			order = append(order, pkHex)
		}
		return e, nil
	}

	for _, a := range atts {
		e, err := entry(a.ValidatorIndex)
		if err != nil {
			return nil, err
		}
		root := a.SigningRoot
		if !domain.HasSigningRoot(root) {
			// 导入进来的缺根历史记录：导出时继续省略 signing_root
			// （规范允许可选），保持“缺失即保守”的语义不被伪造。
			root = nil
		}
		e.SignedAttestations = append(e.SignedAttestations, SignedAttestation{
			SourceEpoch: uint64String(a.SourceEpoch),
			TargetEpoch: uint64String(a.TargetEpoch),
			SigningRoot: hexBytes(root),
		})
	}
	for _, b := range blocks {
		e, err := entry(b.ValidatorIndex)
		if err != nil {
			return nil, err
		}
		root := b.SigningRoot
		if !domain.HasSigningRoot(root) {
			root = nil
		}
		e.SignedBlocks = append(e.SignedBlocks, SignedBlock{
			Slot:        slotPtr(b.Slot),
			SigningRoot: hexBytes(root),
		})
	}

	sort.Slice(order, func(i, j int) bool { return order[i] < order[j] })
	f := File{
		Metadata: Metadata{
			InterchangeFormatVersion: FormatVersion,
			GenesisValidatorsRoot:    hexBytes(genesisValidatorsRoot),
		},
		Data: []ValidatorEntry{},
	}
	for _, pk := range order {
		e := byKey[pk]
		sort.Slice(e.SignedAttestations, func(i, j int) bool {
			a, b := e.SignedAttestations[i], e.SignedAttestations[j]
			if a.TargetEpoch != b.TargetEpoch {
				return a.TargetEpoch < b.TargetEpoch
			}
			return a.SourceEpoch < b.SourceEpoch
		})
		sort.Slice(e.SignedBlocks, func(i, j int) bool {
			return *e.SignedBlocks[i].Slot < *e.SignedBlocks[j].Slot
		})
		f.Data = append(f.Data, *e)
	}
	return json.MarshalIndent(&f, "", "  ")
}

// ExportToFile / ImportFromFile 是文件级便捷封装。
func ExportToFile(path string, st *store.Store, genesisValidatorsRoot []byte,
	indexToPubkey map[uint64][]byte) error {
	data, err := Export(st, genesisValidatorsRoot, indexToPubkey)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func ImportFromFile(st *store.Store, path string, genesisValidatorsRoot []byte, opts Options) (Result, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Result{}, domain.GuardErrorf(domain.ReasonImportInvalid, "cannot read %s: %v", path, err)
	}
	return Import(st, raw, genesisValidatorsRoot, opts)
}

// PubkeyHex 返回规范线格式公钥字符串（0x 前缀）。
func PubkeyHex(pubkey []byte) string { return encodeHex(pubkey) }

func slotPtr(s uint64) *uint64String {
	v := uint64String(s)
	return &v
}
