package domain

import (
	"crypto/ed25519"
	"fmt"
)

// Duty 表示一次待执行的签名职责。
type Duty struct {
	ValidatorIndex uint64
	Slot           uint64
}

// AttestationRequest 是证明签名请求（attestation duty）。
type AttestationRequest struct {
	Duty
	SourceEpoch     uint64
	TargetEpoch     uint64
	BeaconBlockRoot []byte // 被投票的区块根，决定同一 target epoch 下两个证明是否“内容不同”
}

// BlockProposalRequest 是区块提议签名请求（block proposal duty）。
type BlockProposalRequest struct {
	Duty
	ParentRoot []byte
	StateRoot  []byte
	BodyRoot   []byte
}

// SignedResult 是一次签名的确定性产物。
// 同一份记录在任意时刻都能重新派生出完全相同的签名值。
type SignedResult struct {
	SigningRoot []byte
	Signature   []byte
	PublicKey   ed25519.PublicKey
}

// AttestationRecord 是一条已固化的证明防罚没记录（对应 EIP-3076 的 minimum/maximum 语义）。
type AttestationRecord struct {
	ValidatorIndex  uint64
	SourceEpoch     uint64
	TargetEpoch     uint64
	SigningRoot     []byte
	BeaconBlockRoot []byte
	SignedAtSlot    uint64
}

// BlockRecord 是一条已固化的区块提议防罚没记录。
type BlockRecord struct {
	ValidatorIndex uint64
	Slot           uint64
	SigningRoot    []byte
	ParentRoot     []byte
	StateRoot      []byte
	BodyRoot       []byte
}

// SigningRoot 计算证明在给定链头下的签名根（本地模拟，确定性）。
func (r AttestationRequest) SigningRoot(h ChainHead) []byte {
	return hashChunks("attestation/v1", h,
		u64b(r.ValidatorIndex), u64b(r.Slot),
		u64b(r.SourceEpoch), u64b(r.TargetEpoch),
		r.BeaconBlockRoot)
}

// SigningRoot 计算区块提议在给定链头下的签名根。
func (r BlockProposalRequest) SigningRoot(h ChainHead) []byte {
	return hashChunks("block/v1", h,
		u64b(r.ValidatorIndex), u64b(r.Slot),
		r.ParentRoot, r.StateRoot, r.BodyRoot)
}

// 失败原因码：调用方可据此区分不同拒绝原因，互不重叠。
const (
	ReasonStateMismatch      = "STATE_MISMATCH"       // 请求与本地链状态不一致（根 / justified epoch）
	ReasonDutyExpired        = "DUTY_EXPIRED"         // 职责 slot 已落后于链
	ReasonDutyFuture         = "DUTY_FUTURE"          // 职责 slot 尚在未来，无法判定安全性
	ReasonInvalidRequest     = "INVALID_REQUEST"      // 请求字段本身不合法
	ReasonDuplicateDuty      = "DUPLICATE_DUTY"       // 同一职责（签名根）已签署
	ReasonDoubleVote         = "DOUBLE_VOTE"          // 同 target epoch 内容不同的证明
	ReasonSurroundVote       = "SURROUND_VOTE"        // 新区间被既有记录完全包含
	ReasonDuplicateBlockSlot = "DUPLICATE_BLOCK_SLOT" // 同一 slot 的区块重复签署
	ReasonImportConflict     = "IMPORT_CONFLICT"      // 导入数据与既有记录构成罚没冲突
	ReasonImportInvalid      = "IMPORT_INVALID"       // 导入文件格式 / 内容不合法
)

// GuardError 携带可区分原因码与说明，绝不代表“已签署”。
type GuardError struct {
	Reason  string
	Message string
}

func (e *GuardError) Error() string {
	return fmt.Sprintf("slashing guard rejected: %s: %s", e.Reason, e.Message)
}

func guardError(reason, format string, a ...any) *GuardError {
	return &GuardError{Reason: reason, Message: fmt.Sprintf(format, a...)}
}

// GuardErrorf 供 guard 包构造可区分原因的拒绝错误。
func GuardErrorf(reason, format string, a ...any) *GuardError {
	return guardError(reason, format, a...)
}

// DuplicateError 在重复触发时额外附带既有的签名根，便于调用方解释结论。
type DuplicateError struct {
	*GuardError
	ExistingSigningRoot []byte
}

func (e *DuplicateError) Unwrap() error { return e.GuardError }
