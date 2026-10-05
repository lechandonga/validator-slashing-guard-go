package types

import (
	"errors"
	"fmt"
)

// Slot 是链上 slot 编号；Epoch 是 epoch 编号。
// 本项目所有几何关系都基于 SlotsPerEpoch 计算，保证纯本地、确定性。
const SlotsPerEpoch = uint64(8)

// EpochOf 返回 slot 所属的 epoch。
func EpochOf(slot uint64) uint64 { return slot / SlotsPerEpoch }

// Root 模拟以太坊 SSZ Root：32 字节。零值 Root 视为“根未知/未提供”。
type Root [32]byte

// ValidatorID 是本地验证者的稳定标识（模拟公钥哈希）。
type ValidatorID [48]byte

func (v ValidatorID) String() string {
	return fmt.Sprintf("0x%x", v[:8])
}

// Signature 模拟 BLS 签名（96 字节）。它由本地确定性方案生成，
// 仅用于模拟签署结论，不具备真实链上密码学意义。
type Signature [96]byte

// DutyKind 区分职责类型。
type DutyKind string

const (
	DutyAttestation DutyKind = "attestation"
	DutyProposal    DutyKind = "proposal"
)

// AttestationDuty 是一次证明签署请求对应的职责内容。
type AttestationDuty struct {
	Validator       ValidatorID
	Slot            uint64
	BeaconBlockRoot Root
	// TargetEpoch 必须等于 EpochOf(Slot)。
	TargetEpoch uint64
	// SourceEpoch 是证明引用的 source checkpoint epoch。
	SourceEpoch uint64
	SigningRoot Root
}

// ProposalDuty 是一次区块提议签署请求对应的职责内容。
type ProposalDuty struct {
	Validator ValidatorID
	Slot      uint64
	// BlockRoot 是被提议区块的根；同一 slot 不同根即视为双重提议。
	BlockRoot   Root
	SigningRoot Root
}

// SignedAttestation 是已固化的证明防罚没记录。
type SignedAttestation struct {
	SourceEpoch uint64 `json:"source_epoch"`
	TargetEpoch uint64 `json:"target_epoch"`
	// SigningRoot 标识同一 target 下“内容不同”的证明。
	SigningRoot     Root      `json:"signing_root"`
	BeaconBlockRoot Root      `json:"beacon_block_root"`
	Slot            uint64    `json:"slot"`
	Signature       Signature `json:"signature"`
}

// SignedProposal 是已固化的区块提议防罚没记录。
type SignedProposal struct {
	Slot        uint64    `json:"slot"`
	BlockRoot   Root      `json:"block_root"`
	SigningRoot Root      `json:"signing_root"`
	Signature   Signature `json:"signature"`
}

// ValidationError 携带可区分的拒绝原因代码，供调用方精确处理。
type ValidationError struct {
	Reason Reason
	Msg    string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Reason, e.Msg)
}

// Is 使 errors.Is(err, ErrXxx) 可按原因代码匹配。
func (e *ValidationError) Is(target error) bool {
	var t *ValidationError
	if errors.As(target, &t) {
		return e.Reason == t.Reason
	}
	return false
}

// Reason 是拒绝原因代码。
type Reason string

const (
	ReasonMalformed          Reason = "malformed_request"
	ReasonUnknownValidator   Reason = "unknown_validator"
	ReasonStateMismatch      Reason = "state_mismatch"
	ReasonDutyExpired        Reason = "duty_expired"
	ReasonDuplicateDuty      Reason = "duplicate_duty"
	ReasonDoubleAttestation  Reason = "double_attestation"
	ReasonSurrounded         Reason = "surrounded_attestation"
	ReasonSurrounding        Reason = "surrounding_attestation"
	ReasonDoubleProposal     Reason = "double_proposal"
	ReasonInterchangeInvalid Reason = "interchange_invalid"
)

func Fail(reason Reason, format string, args ...any) error {
	return &ValidationError{Reason: reason, Msg: fmt.Sprintf(format, args...)}
}
