// Package interchange 实现 EIP-3076 slashing protection 互换格式的
// 严格解析、校验、安全合并与导出。
// 导入语义：整体校验 + 内存合并，任一冲突则整体拒绝，绝不部分写入。
package interchange

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/lechandonga/validator-slashing-guard-go/internal/store"
	"github.com/lechandonga/validator-slashing-guard-go/internal/types"
)

const interchangeFormatVersion = "5"

// File 是 EIP-3076 顶层结构。
type File struct {
	Metadata Metadata        `json:"metadata"`
	Data     []ValidatorData `json:"data"`
	// 拒绝未知字段，避免静默吞掉可能携带语义的信息。
}

type Metadata struct {
	InterchangeFormatVersion string `json:"interchange_format_version"`
	GenesisValidatorsRoot    string `json:"genesis_validators_root"`
}

type ValidatorData struct {
	PublicKey          string              `json:"pubkey"`
	SignedBlocks       []SignedBlock       `json:"signed_blocks"`
	SignedAttestations []SignedAttestation `json:"signed_attestations"`
}

type SignedBlock struct {
	Slot        uint64 `json:"slot,string"`
	SigningRoot string `json:"signing_root"`
}

type SignedAttestation struct {
	SourceEpoch uint64 `json:"source_epoch,string"`
	TargetEpoch uint64 `json:"target_epoch,string"`
	SigningRoot string `json:"signing_root"`
}

func decodeRoot(s, what string) (types.Root, error) {
	var r types.Root
	if s == "" {
		return r, fmt.Errorf("%s is empty", what)
	}
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		return r, fmt.Errorf("%s is not valid hex: %w", what, err)
	}
	if len(b) != 32 {
		return r, fmt.Errorf("%s must be 32 bytes, got %d", what, len(b))
	}
	copy(r[:], b)
	return r, nil
}

func decodeValidator(s string) (types.ValidatorID, error) {
	var v types.ValidatorID
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		return v, fmt.Errorf("pubkey is not valid hex: %w", err)
	}
	if len(b) != 48 {
		return v, fmt.Errorf("pubkey must be 48 bytes, got %d", len(b))
	}
	copy(v[:], b)
	return v, nil
}

// ImportResult 是整体合并的结论。
type ImportResult struct {
	NewAttestations int
	NewProposals    int
}

// Import 严格解析 interchange 数据，与现有记录在内存中安全合并，
// 全部通过后才通过 st 原子提交；任何错误均不触碰既有记录。
func Import(raw []byte, validator types.ValidatorID, gvr types.Root, st *store.Store) (ImportResult, error) {
	var f File
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return ImportResult{}, types.Fail(types.ReasonInterchangeInvalid, "parse interchange file: %v", err)
	}
	if dec.More() {
		return ImportResult{}, types.Fail(types.ReasonInterchangeInvalid, "interchange file contains trailing data")
	}

	if f.Metadata.InterchangeFormatVersion != interchangeFormatVersion {
		return ImportResult{}, types.Fail(types.ReasonInterchangeInvalid,
			"unsupported interchange_format_version %q, require %q", f.Metadata.InterchangeFormatVersion, interchangeFormatVersion)
	}
	wantGVR := "0x" + hex.EncodeToString(gvr[:])
	if !strings.EqualFold(f.Metadata.GenesisValidatorsRoot, wantGVR) {
		return ImportResult{}, types.Fail(types.ReasonInterchangeInvalid,
			"genesis_validators_root mismatch: file has %s, local is %s", f.Metadata.GenesisValidatorsRoot, wantGVR)
	}
	if len(f.Data) == 0 {
		return ImportResult{}, types.Fail(types.ReasonInterchangeInvalid, "interchange contains no validator data")
	}
	wantKey := "0x" + hex.EncodeToString(validator[:])
	if len(f.Data) != 1 || !strings.EqualFold(f.Data[0].PublicKey, wantKey) {
		return ImportResult{}, types.Fail(types.ReasonInterchangeInvalid,
			"interchange must contain exactly the local validator %s", wantKey)
	}

	vd := f.Data[0]
	attestations := st.Attestations()
	proposals := st.Proposals()

	res := ImportResult{}

	for i, a := range vd.SignedAttestations {
		if a.SourceEpoch > a.TargetEpoch {
			return ImportResult{}, types.Fail(types.ReasonInterchangeInvalid,
				"attestation #%d has source %d greater than target %d", i, a.SourceEpoch, a.TargetEpoch)
		}
		sr, err := decodeRoot(a.SigningRoot, fmt.Sprintf("attestation #%d signing_root", i))
		if err != nil {
			return ImportResult{}, types.Fail(types.ReasonInterchangeInvalid, "%v", err)
		}
		// 与“既有 + 已通过导入”的全部记录做几何/冲突检查。
		for j, rec := range attestations {
			switch {
			case rec.SigningRoot == sr:
				// 完全相同的记录视为幂等重导入，跳过。
				if rec.SourceEpoch == a.SourceEpoch && rec.TargetEpoch == a.TargetEpoch {
					goto nextAtt
				}
				return ImportResult{}, types.Fail(types.ReasonInterchangeInvalid,
					"attestation #%d reuses signing root with different epochs vs record #%d", i, j)
			case rec.TargetEpoch == a.TargetEpoch:
				return ImportResult{}, types.Fail(types.ReasonDoubleAttestation,
					"attestation #%d conflicts with record #%d: same target epoch %d with different content", i, j, a.TargetEpoch)
			case rec.SourceEpoch < a.SourceEpoch && a.TargetEpoch < rec.TargetEpoch:
				return ImportResult{}, types.Fail(types.ReasonSurrounded,
					"attestation #%d [%d,%d] is contained in record #%d [%d,%d]", i, a.SourceEpoch, a.TargetEpoch, j, rec.SourceEpoch, rec.TargetEpoch)
			case a.SourceEpoch < rec.SourceEpoch && rec.TargetEpoch < a.TargetEpoch:
				return ImportResult{}, types.Fail(types.ReasonSurrounding,
					"attestation #%d [%d,%d] surrounds record #%d [%d,%d]", i, a.SourceEpoch, a.TargetEpoch, j, rec.SourceEpoch, rec.TargetEpoch)
			}
		}
		attestations = append(attestations, types.SignedAttestation{
			SourceEpoch: a.SourceEpoch,
			TargetEpoch: a.TargetEpoch,
			SigningRoot: sr,
			Slot:        a.TargetEpoch * types.SlotsPerEpoch,
		})
		res.NewAttestations++
	nextAtt:
	}

	for i, b := range vd.SignedBlocks {
		sr, err := decodeRoot(b.SigningRoot, fmt.Sprintf("block #%d signing_root", i))
		if err != nil {
			return ImportResult{}, types.Fail(types.ReasonInterchangeInvalid, "%v", err)
		}
		for j, rec := range proposals {
			if rec.Slot != b.Slot {
				continue
			}
			if rec.SigningRoot == sr {
				goto nextBlock
			}
			return ImportResult{}, types.Fail(types.ReasonDoubleProposal,
				"block #%d at slot %d conflicts with record #%d: same slot, different block", i, b.Slot, j)
		}
		proposals = append(proposals, types.SignedProposal{
			Slot:        b.Slot,
			SigningRoot: sr,
			BlockRoot:   sr,
		})
		res.NewProposals++
	nextBlock:
	}

	// 所有检查在内存完成后，单次原子提交。
	if err := st.CommitReplacement(attestations, proposals); err != nil {
		return ImportResult{}, err
	}
	return res, nil
}

// Export 把当前记录导出为标准 EIP-3076 文件（规范排序，可复现）。
func Export(st *store.Store, validator types.ValidatorID, gvr types.Root) ([]byte, error) {
	atts := st.Attestations()
	props := st.Proposals()

	sort.Slice(atts, func(i, j int) bool {
		if atts[i].TargetEpoch != atts[j].TargetEpoch {
			return atts[i].TargetEpoch < atts[j].TargetEpoch
		}
		return atts[i].SourceEpoch < atts[j].SourceEpoch
	})
	sort.Slice(props, func(i, j int) bool { return props[i].Slot < props[j].Slot })

	vd := ValidatorData{PublicKey: "0x" + hex.EncodeToString(validator[:])}
	for _, a := range atts {
		vd.SignedAttestations = append(vd.SignedAttestations, SignedAttestation{
			SourceEpoch: a.SourceEpoch,
			TargetEpoch: a.TargetEpoch,
			SigningRoot: "0x" + hex.EncodeToString(a.SigningRoot[:]),
		})
	}
	for _, p := range props {
		vd.SignedBlocks = append(vd.SignedBlocks, SignedBlock{
			Slot:        p.Slot,
			SigningRoot: "0x" + hex.EncodeToString(p.SigningRoot[:]),
		})
	}
	f := File{
		Metadata: Metadata{
			InterchangeFormatVersion: interchangeFormatVersion,
			GenesisValidatorsRoot:    "0x" + hex.EncodeToString(gvr[:]),
		},
		Data: []ValidatorData{vd},
	}
	return json.MarshalIndent(f, "", "  ")
}
