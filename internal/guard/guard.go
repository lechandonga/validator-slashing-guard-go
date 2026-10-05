// Package guard 实现签名准入与防罚没保护。
//
// 安全模型（崩溃安全）：
//  1. 准入校验、防罚没判定与记录固化在同一个互斥临界区内串行完成；
//  2. 记录固化（原子 rename + fsync）先于签名值返回；
//  3. 签名是 (validator key, signing root) 的确定性函数（Ed25519/RFC 8032），
//     已固化的记录在任意时刻都能重新派生出完全相同的签名。
//
// 因此崩溃重启后不存在“已签名却无记录”，也不会把未签署的职责当成已签。
package guard

import (
	"bytes"
	"crypto/ed25519"

	"github.com/lechandonga/validator-slashing-guard-go/internal/domain"
	"github.com/lechandonga/validator-slashing-guard-go/internal/store"
)

// Validator 是本地验证者的签名身份。
type Validator struct {
	Index      uint64
	PublicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
}

func NewValidator(index uint64, priv ed25519.PrivateKey) *Validator {
	pub := priv.Public().(ed25519.PublicKey)
	return &Validator{Index: index, PublicKey: append(ed25519.PublicKey(nil), pub...), privateKey: priv}
}

// Client 是签名客户端：持有链状态、记录存储与验证者身份。
type Client struct {
	state *domain.ChainState
	store *store.Store
	val   *Validator
}

func NewClient(state *domain.ChainState, st *store.Store, val *Validator) *Client {
	return &Client{state: state, store: st, val: val}
}

// Store 暴露记录存储（导入/导出等需要直接访问）。
func (c *Client) Store() *store.Store { return c.store }

// SignAttestation 执行一次证明签名职责。
// 返回 GuardError 时一定没有产生任何新签名与新记录。
func (c *Client) SignAttestation(req domain.AttestationRequest) (domain.SignedResult, error) {
	head := c.state.Snapshot()

	var res domain.SignedResult
	err := c.store.Update(func(atts []domain.AttestationRecord, blocks []domain.BlockRecord) (
		[]domain.AttestationRecord, []domain.BlockRecord, error) {

		if err := ValidateAttestation(req, head); err != nil {
			return nil, nil, err
		}
		signingRoot := req.SigningRoot(head)

		if existing, reason := FindAttestationConflict(req.ValidatorIndex, req.SourceEpoch, req.TargetEpoch,
			req.BeaconBlockRoot, signingRoot, atts); reason != "" {
			return nil, nil, &domain.DuplicateError{
				GuardError:          domain.GuardErrorf(reason, "%s", ConflictMessage(reason)),
				ExistingSigningRoot: dup(existing),
			}
		}

		rec := domain.AttestationRecord{
			ValidatorIndex:  req.ValidatorIndex,
			SourceEpoch:     req.SourceEpoch,
			TargetEpoch:     req.TargetEpoch,
			SigningRoot:     signingRoot,
			BeaconBlockRoot: append([]byte(nil), req.BeaconBlockRoot...),
			SignedAtSlot:    head.CurrentSlot,
		}
		res = c.sign(signingRoot)
		return append(atts, rec), blocks, nil
	})
	return res, err
}

// SignBlock 执行一次区块提议签名职责。
func (c *Client) SignBlock(req domain.BlockProposalRequest) (domain.SignedResult, error) {
	head := c.state.Snapshot()

	var res domain.SignedResult
	err := c.store.Update(func(atts []domain.AttestationRecord, blocks []domain.BlockRecord) (
		[]domain.AttestationRecord, []domain.BlockRecord, error) {

		if err := ValidateBlock(req, head); err != nil {
			return nil, nil, err
		}
		signingRoot := req.SigningRoot(head)

		for _, b := range blocks {
			if b.ValidatorIndex != req.ValidatorIndex || b.Slot != req.Slot {
				continue
			}
			if bytes.Equal(b.SigningRoot, signingRoot) {
				return nil, nil, &domain.DuplicateError{
					GuardError: domain.GuardErrorf(domain.ReasonDuplicateDuty,
						"block proposal at slot %d already signed", req.Slot),
					ExistingSigningRoot: append([]byte(nil), b.SigningRoot...),
				}
			}
			return nil, nil, domain.GuardErrorf(domain.ReasonDuplicateBlockSlot,
				"different block already signed for validator %d at slot %d", req.ValidatorIndex, req.Slot)
		}

		rec := domain.BlockRecord{
			ValidatorIndex: req.ValidatorIndex,
			Slot:           req.Slot,
			SigningRoot:    signingRoot,
			ParentRoot:     append([]byte(nil), req.ParentRoot...),
			StateRoot:      append([]byte(nil), req.StateRoot...),
			BodyRoot:       append([]byte(nil), req.BodyRoot...),
		}
		res = c.sign(signingRoot)
		return atts, append(blocks, rec), nil
	})
	return res, err
}

// sign 是确定性签名：相同私钥 + 相同签名根永远得到相同签名。
func (c *Client) sign(signingRoot []byte) domain.SignedResult {
	sig := ed25519.Sign(c.val.privateKey, signingRoot)
	return domain.SignedResult{
		SigningRoot: append([]byte(nil), signingRoot...),
		Signature:   sig,
		PublicKey:   append(ed25519.PublicKey(nil), c.val.PublicKey...),
	}
}

// ReplaySignature 依据已固化记录重新派生签名（崩溃恢复后的解释/重放，而非重新签署）。
func (c *Client) ReplaySignature(signingRoot []byte) domain.SignedResult {
	return c.sign(signingRoot)
}

// ValidateAttestation 是证明签名准入规则（纯函数，导入与签名共用）。
func ValidateAttestation(req domain.AttestationRequest, h domain.ChainHead) error {
	if len(req.BeaconBlockRoot) == 0 {
		return domain.GuardErrorf(domain.ReasonInvalidRequest, "beacon block root is empty")
	}
	if req.TargetEpoch != domain.EpochOf(req.Slot) {
		return domain.GuardErrorf(domain.ReasonInvalidRequest,
			"target epoch %d does not match slot %d epoch %d",
			req.TargetEpoch, req.Slot, domain.EpochOf(req.Slot))
	}
	if req.SourceEpoch > req.TargetEpoch {
		return domain.GuardErrorf(domain.ReasonInvalidRequest,
			"source epoch %d greater than target epoch %d", req.SourceEpoch, req.TargetEpoch)
	}
	cur := h.CurrentSlot
	if req.Slot < cur {
		return domain.GuardErrorf(domain.ReasonDutyExpired,
			"duty slot %d is behind chain slot %d", req.Slot, cur)
	}
	if req.Slot > cur {
		return domain.GuardErrorf(domain.ReasonDutyFuture,
			"duty slot %d is ahead of chain slot %d", req.Slot, cur)
	}
	// 请求必须与本地链状态一致：投票根必须是当前头根，source 必须是当前 justified epoch。
	if !bytes.Equal(req.BeaconBlockRoot, h.HeadRoot) {
		return domain.GuardErrorf(domain.ReasonStateMismatch,
			"attestation block root does not match local head")
	}
	if req.SourceEpoch != h.JustifiedEpoch {
		return domain.GuardErrorf(domain.ReasonStateMismatch,
			"source epoch %d != local justified epoch %d", req.SourceEpoch, h.JustifiedEpoch)
	}
	return nil
}

// ValidateBlock 是区块提议签名准入规则（纯函数）。
func ValidateBlock(req domain.BlockProposalRequest, h domain.ChainHead) error {
	if len(req.ParentRoot) == 0 || len(req.StateRoot) == 0 || len(req.BodyRoot) == 0 {
		return domain.GuardErrorf(domain.ReasonInvalidRequest, "block roots must not be empty")
	}
	cur := h.CurrentSlot
	if req.Slot < cur {
		return domain.GuardErrorf(domain.ReasonDutyExpired,
			"proposal slot %d is behind chain slot %d", req.Slot, cur)
	}
	if req.Slot > cur {
		return domain.GuardErrorf(domain.ReasonDutyFuture,
			"proposal slot %d is ahead of chain slot %d", req.Slot, cur)
	}
	return nil
}

// FindAttestationConflict 返回 (冲突的既有记录, 拒绝原因)。
// 原因优先级：完全重复 > double vote > surround vote。
func FindAttestationConflict(validatorIndex, reqSource, reqTarget uint64,
	blockRoot, signingRoot []byte, atts []domain.AttestationRecord) (*domain.AttestationRecord, string) {

	var double *domain.AttestationRecord
	var surround *domain.AttestationRecord
	for i := range atts {
		old := &atts[i]
		if old.ValidatorIndex != validatorIndex {
			continue
		}
		if bytes.Equal(old.SigningRoot, signingRoot) {
			return old, domain.ReasonDuplicateDuty
		}
		if double == nil && old.TargetEpoch == reqTarget &&
			!bytes.Equal(old.BeaconBlockRoot, blockRoot) {
			double = old
		}
		// 新区间 (source,target) 被既有区间严格包含 => surrounded 罚没。
		if surround == nil && old.SourceEpoch < reqSource && old.TargetEpoch > reqTarget {
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

// ConflictMessage 返回各冲突原因的可解释说明。
func ConflictMessage(reason string) string {
	switch reason {
	case domain.ReasonDuplicateDuty:
		return "identical duty already signed (same signing root)"
	case domain.ReasonDoubleVote:
		return "different attestation already signed for the same target epoch"
	case domain.ReasonSurroundVote:
		return "attestation span is fully contained by an existing record (surround vote)"
	}
	return "attestation conflicts with existing record"
}

func dup(old *domain.AttestationRecord) []byte {
	if old == nil {
		return nil
	}
	return append([]byte(nil), old.SigningRoot...)
}
