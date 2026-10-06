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
	"sort"
	"sync"

	"github.com/lechandonga/validator-slashing-guard-go/internal/domain"
	"github.com/lechandonga/validator-slashing-guard-go/internal/store"
)

// Validator 是本地验证者的签名身份。
type Validator struct {
	Index        uint64
	PublicKey    ed25519.PublicKey // 签名密钥公钥（本地 Ed25519 确定性签名用）
	BeaconPubKey []byte            // 链上 BLS 公钥（48 字节，EIP-3076 身份键）
	privateKey   ed25519.PrivateKey
}

// NewValidator 创建一个本地签名身份。beaconPubKey 是该验证者的链上 BLS
// 公钥（48 字节），作为互导文件中的身份键与多身份归属依据。
func NewValidator(index uint64, beaconPubKey []byte, priv ed25519.PrivateKey) *Validator {
	pub := priv.Public().(ed25519.PublicKey)
	return &Validator{
		Index:        index,
		PublicKey:    append(ed25519.PublicKey(nil), pub...),
		BeaconPubKey: append([]byte(nil), beaconPubKey...),
		privateKey:   priv,
	}
}

// Client 是签名客户端：持有链状态、记录存储与验证者身份。
type Client struct {
	state      *domain.ChainState
	store      *store.Store
	mu         sync.RWMutex
	validators map[uint64]*Validator
	byPubkey   map[string]uint64
}

// NewClient 创建托管多个验证者身份的客户端。所有身份共用链状态与记录存储，
// 记录按身份索引隔离，判定与导出均不串用。
func NewClient(state *domain.ChainState, st *store.Store, vals ...*Validator) *Client {
	c := &Client{
		state:      state,
		store:      st,
		validators: map[uint64]*Validator{},
		byPubkey:   map[string]uint64{},
	}
	for _, v := range vals {
		c.AddValidator(v)
	}
	return c
}

// AddValidator 注册一个本地托管身份。索引与 BLS 公钥都必须唯一。
func (c *Client) AddValidator(v *Validator) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.validators[v.Index]; exists {
		panic("guard: duplicate validator index registered")
	}
	key := string(v.BeaconPubKey)
	if _, exists := c.byPubkey[key]; exists {
		panic("guard: duplicate validator pubkey registered")
	}
	c.validators[v.Index] = v
	c.byPubkey[key] = v.Index
}

func (c *Client) validator(index uint64) (*Validator, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	v, ok := c.validators[index]
	if !ok {
		return nil, domain.GuardErrorf(domain.ReasonUnknownValidator,
			"validator index %d is not hosted locally", index)
	}
	return v, nil
}

// ValidatorIndexByPubkey / PubkeyByValidatorIndex / HostedValidators
// 实现 interchange.ValidatorDirectory，供互导按身份合并与导出。
func (c *Client) ValidatorIndexByPubkey(pubkey []byte) (uint64, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	index, ok := c.byPubkey[string(pubkey)]
	return index, ok
}

func (c *Client) PubkeyByValidatorIndex(index uint64) ([]byte, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	v, ok := c.validators[index]
	if !ok {
		return nil, false
	}
	return append([]byte(nil), v.BeaconPubKey...), true
}

func (c *Client) HostedValidators() []uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]uint64, 0, len(c.validators))
	for index := range c.validators {
		out = append(out, index)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Store 暴露记录存储（导入/导出等需要直接访问）。
func (c *Client) Store() *store.Store { return c.store }

// SignAttestation 执行一次证明签名职责。
// 返回 GuardError 时一定没有产生任何新签名与新记录。
func (c *Client) SignAttestation(req domain.AttestationRequest) (domain.SignedResult, error) {
	val, err := c.validator(req.ValidatorIndex)
	if err != nil {
		return domain.SignedResult{}, err
	}
	head := c.state.Snapshot()

	var res domain.SignedResult
	err = c.store.Update(func(atts []domain.AttestationRecord, blocks []domain.BlockRecord) (
		[]domain.AttestationRecord, []domain.BlockRecord, error) {

		if err := ValidateAttestation(req, head, val.BeaconPubKey); err != nil {
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
		res = c.sign(val, signingRoot)
		return append(atts, rec), blocks, nil
	})
	return res, err
}

// SignBlock 执行一次区块提议签名职责。
func (c *Client) SignBlock(req domain.BlockProposalRequest) (domain.SignedResult, error) {
	val, err := c.validator(req.ValidatorIndex)
	if err != nil {
		return domain.SignedResult{}, err
	}
	head := c.state.Snapshot()

	var res domain.SignedResult
	err = c.store.Update(func(atts []domain.AttestationRecord, blocks []domain.BlockRecord) (
		[]domain.AttestationRecord, []domain.BlockRecord, error) {

		if err := ValidateBlock(req, head, val.BeaconPubKey); err != nil {
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
		res = c.sign(val, signingRoot)
		return atts, append(blocks, rec), nil
	})
	return res, err
}

// sign 是确定性签名：相同私钥 + 相同签名根永远得到相同签名。
func (c *Client) sign(val *Validator, signingRoot []byte) domain.SignedResult {
	sig := ed25519.Sign(val.privateKey, signingRoot)
	return domain.SignedResult{
		SigningRoot: append([]byte(nil), signingRoot...),
		Signature:   sig,
		PublicKey:   append(ed25519.PublicKey(nil), val.PublicKey...),
	}
}

// ReplaySignature 依据已固化记录重新派生签名（崩溃恢复后的解释/重放，而非重新签署）。
func (c *Client) ReplaySignature(validatorIndex uint64, signingRoot []byte) (domain.SignedResult, error) {
	val, err := c.validator(validatorIndex)
	if err != nil {
		return domain.SignedResult{}, err
	}
	return c.sign(val, signingRoot), nil
}

// ValidateAttestation 是证明签名准入规则（纯函数）。
// expectedPubKey 是该索引在本地托管身份的 BLS 公钥：请求携带的身份与之
// 不一致时以 IDENTITY_MISMATCH 拒绝，绝不签署、绝不留记录。
func ValidateAttestation(req domain.AttestationRequest, h domain.ChainHead, expectedPubKey []byte) error {
	if err := validateIdentity(req.ValidatorIndex, req.BeaconPublicKey, expectedPubKey); err != nil {
		return err
	}
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
func ValidateBlock(req domain.BlockProposalRequest, h domain.ChainHead, expectedPubKey []byte) error {
	if err := validateIdentity(req.ValidatorIndex, req.BeaconPublicKey, expectedPubKey); err != nil {
		return err
	}
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

func validateIdentity(index uint64, requestedPubKey, expectedPubKey []byte) error {
	if len(requestedPubKey) == 0 {
		return domain.GuardErrorf(domain.ReasonIdentityMismatch,
			"duty for validator %d carries no validator public key", index)
	}
	if !bytes.Equal(requestedPubKey, expectedPubKey) {
		return domain.GuardErrorf(domain.ReasonIdentityMismatch,
			"duty public key for validator %d does not match the locally hosted identity "+
				"(requested=0x%x, hosted=0x%x)",
			index, requestedPubKey, expectedPubKey)
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
		// 区间互相严格包含任一方向都构成 surround 罚没。
		if surround == nil &&
			((old.SourceEpoch < reqSource && old.TargetEpoch > reqTarget) ||
				(reqSource < old.SourceEpoch && reqTarget > old.TargetEpoch)) {
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
