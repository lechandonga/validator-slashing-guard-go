// Package guard 实现签名准入与防罚没保护。
//
// 安全模型（崩溃安全）：
//  1. 准入校验、身份校验、防罚没判定与记录固化在同一个互斥临界区内串行完成；
//  2. 记录固化（原子 rename + fsync）先于签名值返回；
//  3. 签名是 (validator key, signing root) 的确定性函数（Ed25519/RFC 8032），
//     已固化的记录在任意时刻都能重新派生出完全相同的签名。
//
// 一个 Client 同时托管多个验证者身份：职责按身份落到对应密钥与记录分区，
// 身份不匹配或身份不存在一律拒绝，不签署、不留痕。
package guard

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"sort"

	"github.com/lechandonga/validator-slashing-guard-go/internal/domain"
	"github.com/lechandonga/validator-slashing-guard-go/internal/store"
)

// Validator 是本地验证者的签名身份。
type Validator struct {
	Index      uint64
	PublicKey  []byte // 对外（EIP-3076）身份：48 字节 BLS 公钥
	privateKey ed25519.PrivateKey
}

// NewValidator 注册一个验证者身份，外部公钥按索引确定性派生（仅本地模拟）。
func NewValidator(index uint64, priv ed25519.PrivateKey) *Validator {
	return NewValidatorWithPubkey(index, DeriveExternalPubkey(index), priv)
}

// NewValidatorWithPubkey 用显式的 48 字节外部公钥构造身份（互导时对齐真实客户端）。
func NewValidatorWithPubkey(index uint64, externalPubkey []byte, priv ed25519.PrivateKey) *Validator {
	return &Validator{
		Index:      index,
		PublicKey:  append([]byte(nil), externalPubkey...),
		privateKey: priv,
	}
}

// DeriveExternalPubkey 为给定索引确定性派生一个 48 字节“BLS 公钥”。
// 仅用于本地模拟：真实部署中公钥来自存款凭据，不由索引派生。
func DeriveExternalPubkey(index uint64) []byte {
	w := sha256.New()
	w.Write([]byte("local/bls-pubkey/v1"))
	w.Write(u64b(index))
	sum := w.Sum(nil)
	pub := make([]byte, 48)
	copy(pub, sum)
	copy(pub[32:], sum[:16])
	return pub
}

// Client 是多验证者签名客户端：持有链状态、记录存储与托管身份集合。
type Client struct {
	state *domain.ChainState
	store *store.Store
	vals  map[uint64]*Validator
}

// NewClient 创建多验证者客户端，vals 为初始托管身份集合（可为空）。
func NewClient(state *domain.ChainState, st *store.Store, vals ...*Validator) *Client {
	c := &Client{state: state, store: st, vals: map[uint64]*Validator{}}
	for _, v := range vals {
		c.vals[v.Index] = v
	}
	return c
}

// AddValidator 托管一个新的验证者身份；重复添加同一索引返回错误。
func (c *Client) AddValidator(v *Validator) error {
	if _, exists := c.vals[v.Index]; exists {
		return domain.GuardErrorf(domain.ReasonInvalidRequest,
			"validator index %d already registered", v.Index)
	}
	c.vals[v.Index] = v
	return nil
}

// Validator 返回已托管身份（按索引）。
func (c *Client) Validator(index uint64) (*Validator, bool) {
	v, ok := c.vals[index]
	return v, ok
}

// Validators 返回全部已托管身份（顺序稳定，按索引升序）。
func (c *Client) Validators() []*Validator {
	idxs := make([]uint64, 0, len(c.vals))
	for i := range c.vals {
		idxs = append(idxs, i)
	}
	sort.Slice(idxs, func(i, j int) bool { return idxs[i] < idxs[j] })
	out := make([]*Validator, 0, len(idxs))
	for _, i := range idxs {
		out = append(out, c.vals[i])
	}
	return out
}

// Store 暴露记录存储（导入/导出等需要直接访问）。
func (c *Client) Store() *store.Store { return c.store }

// SignAttestation 执行一次证明签名职责。signerIndex 是本次签署使用的身份：
// 它必须等于 req.ValidatorIndex 且已托管，否则明确拒绝，不签署、不留痕。
func (c *Client) SignAttestation(signerIndex uint64, req domain.AttestationRequest) (domain.SignedResult, error) {
	val, err := c.identity(signerIndex, req.ValidatorIndex)
	if err != nil {
		return domain.SignedResult{}, err
	}
	head := c.state.Snapshot()

	var res domain.SignedResult
	err = c.store.Update(func(atts []domain.AttestationRecord, blocks []domain.BlockRecord) (
		[]domain.AttestationRecord, []domain.BlockRecord, error) {

		if err := ValidateAttestation(req, head); err != nil {
			return nil, nil, err
		}
		signingRoot := req.SigningRoot(head)

		if existing, reason := FindAttestationConflict(req.ValidatorIndex, req.SourceEpoch, req.TargetEpoch,
			signingRoot, atts); reason != "" {
			return nil, nil, &domain.DuplicateError{
				GuardError:          domain.GuardErrorf(reason, "%s", ConflictMessage(reason)),
				ExistingSigningRoot: dup(existing),
			}
		}
		if minSource, minTarget, ok := attestationWatermark(req.ValidatorIndex, atts); ok &&
			(req.SourceEpoch < minSource || req.TargetEpoch <= minTarget) {
			return nil, nil, domain.GuardErrorf(domain.ReasonHistoryWatermark,
				"attestation source=%d target=%d is below history watermark (min source=%d min target=%d)",
				req.SourceEpoch, req.TargetEpoch, minSource, minTarget)
		}

		rec := domain.AttestationRecord{
			ValidatorIndex:  req.ValidatorIndex,
			SourceEpoch:     req.SourceEpoch,
			TargetEpoch:     req.TargetEpoch,
			SigningRoot:     signingRoot,
			BeaconBlockRoot: append([]byte(nil), req.BeaconBlockRoot...),
			SignedAtSlot:    head.CurrentSlot,
		}
		res = val.sign(signingRoot)
		return append(atts, rec), blocks, nil
	})
	return res, err
}

// SignBlock 执行一次区块提议签名职责；身份规则同 SignAttestation。
func (c *Client) SignBlock(signerIndex uint64, req domain.BlockProposalRequest) (domain.SignedResult, error) {
	val, err := c.identity(signerIndex, req.ValidatorIndex)
	if err != nil {
		return domain.SignedResult{}, err
	}
	head := c.state.Snapshot()

	var res domain.SignedResult
	err = c.store.Update(func(atts []domain.AttestationRecord, blocks []domain.BlockRecord) (
		[]domain.AttestationRecord, []domain.BlockRecord, error) {

		if err := ValidateBlock(req, head); err != nil {
			return nil, nil, err
		}
		signingRoot := req.SigningRoot(head)

		if existing, reason := FindBlockConflict(req.ValidatorIndex, req.Slot, signingRoot, blocks); reason != "" {
			if reason == domain.ReasonDuplicateDuty {
				return nil, nil, &domain.DuplicateError{
					GuardError: domain.GuardErrorf(domain.ReasonDuplicateDuty,
						"block proposal at slot %d already signed", req.Slot),
					ExistingSigningRoot: append([]byte(nil), existing.SigningRoot...),
				}
			}
			return nil, nil, domain.GuardErrorf(reason, "%s", ConflictMessage(reason))
		}

		rec := domain.BlockRecord{
			ValidatorIndex: req.ValidatorIndex,
			Slot:           req.Slot,
			SigningRoot:    signingRoot,
			ParentRoot:     append([]byte(nil), req.ParentRoot...),
			StateRoot:      append([]byte(nil), req.StateRoot...),
			BodyRoot:       append([]byte(nil), req.BodyRoot...),
		}
		res = val.sign(signingRoot)
		return atts, append(blocks, rec), nil
	})
	return res, err
}

// identity 校验“本次签署使用的身份”与“职责声明的身份”一致且已托管。
// 该检查在进入存储临界区之前完成：失败绝不写入任何身份的记录。
func (c *Client) identity(signerIndex, requestIndex uint64) (*Validator, error) {
	if signerIndex != requestIndex {
		return nil, domain.GuardErrorf(domain.ReasonValidatorMismatch,
			"signing identity %d does not match duty identity %d", signerIndex, requestIndex)
	}
	v, ok := c.vals[signerIndex]
	if !ok {
		return nil, domain.GuardErrorf(domain.ReasonUnknownValidator,
			"validator %d is not hosted by this client", signerIndex)
	}
	return v, nil
}

// sign 是确定性签名：相同私钥 + 相同签名根永远得到相同签名。
func (v *Validator) sign(signingRoot []byte) domain.SignedResult {
	sig := ed25519.Sign(v.privateKey, signingRoot)
	return domain.SignedResult{
		SigningRoot: append([]byte(nil), signingRoot...),
		Signature:   sig,
		PublicKey:   append([]byte(nil), v.PublicKey...),
	}
}

// ReplaySignature 依据已固化记录重新派生签名（崩溃恢复后的解释/重放，而非重新签署）。
func (c *Client) ReplaySignature(validatorIndex uint64, signingRoot []byte) (domain.SignedResult, error) {
	v, ok := c.vals[validatorIndex]
	if !ok {
		return domain.SignedResult{}, domain.GuardErrorf(domain.ReasonUnknownValidator,
			"validator %d is not hosted by this client", validatorIndex)
	}
	return v.sign(signingRoot), nil
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
// 记录可缺失签名根（内部为 DummySigningRoot），此时无法证明“同一次签署内容”，
// 同 target 的任何差异都按 double vote 保守拒绝。
func FindAttestationConflict(validatorIndex, reqSource, reqTarget uint64,
	signingRoot []byte, atts []domain.AttestationRecord) (*domain.AttestationRecord, string) {

	// 第一遍：只有双方签名根都真实存在时，才能判定“完全重复”。
	if domain.HasSigningRoot(signingRoot) {
		for i := range atts {
			old := &atts[i]
			if old.ValidatorIndex == validatorIndex && bytes.Equal(old.SigningRoot, signingRoot) {
				return old, domain.ReasonDuplicateDuty
			}
		}
	}

	var double *domain.AttestationRecord
	var surround *domain.AttestationRecord
	for i := range atts {
		old := &atts[i]
		if old.ValidatorIndex != validatorIndex {
			continue
		}
		if old.TargetEpoch == reqTarget {
			sameContent := domain.HasSigningRoot(signingRoot) &&
				domain.HasSigningRoot(old.SigningRoot) &&
				bytes.Equal(old.SigningRoot, signingRoot)
			if !sameContent && double == nil {
				double = old
			}
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

// FindBlockConflict 判定同一验证者的区块冲突：
// 签名根相同 => DUPLICATE_DUTY；同 slot 根不同（或缺根无法证明相同）
// => DUPLICATE_BLOCK_SLOT；slot 低于历史最小 slot（EIP-3076 条件 2）
// => HISTORY_WATERMARK。
func FindBlockConflict(validatorIndex, slot uint64, signingRoot []byte,
	blocks []domain.BlockRecord) (*domain.BlockRecord, string) {

	var minSlot uint64
	haveMin := false
	for i := range blocks {
		old := &blocks[i]
		if old.ValidatorIndex != validatorIndex {
			continue
		}
		if !haveMin || old.Slot < minSlot {
			minSlot, haveMin = old.Slot, true
		}
		if old.Slot != slot {
			continue
		}
		sameContent := domain.HasSigningRoot(signingRoot) &&
			domain.HasSigningRoot(old.SigningRoot) &&
			bytes.Equal(old.SigningRoot, signingRoot)
		if sameContent {
			return old, domain.ReasonDuplicateDuty
		}
		return old, domain.ReasonDuplicateBlockSlot
	}
	if haveMin && slot <= minSlot {
		// 相等已在上面处理；此处是 slot < 历史最小 slot。
		for i := range blocks {
			if blocks[i].ValidatorIndex == validatorIndex {
				return &blocks[i], domain.ReasonHistoryWatermark
			}
		}
	}
	return nil, ""
}

// attestationWatermark 返回该验证者的 (最小 source, 最小 target) 历史低水位
// （EIP-3076 条件 4/5）；无记录时 ok=false。
func attestationWatermark(validatorIndex uint64, atts []domain.AttestationRecord) (uint64, uint64, bool) {
	var minSource, minTarget uint64
	have := false
	for i := range atts {
		old := &atts[i]
		if old.ValidatorIndex != validatorIndex {
			continue
		}
		if !have {
			minSource, minTarget, have = old.SourceEpoch, old.TargetEpoch, true
			continue
		}
		if old.SourceEpoch < minSource {
			minSource = old.SourceEpoch
		}
		if old.TargetEpoch < minTarget {
			minTarget = old.TargetEpoch
		}
	}
	return minSource, minTarget, have
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
	case domain.ReasonDuplicateBlockSlot:
		return "different block already signed at the same slot (or signing root missing, cannot prove equality)"
	case domain.ReasonHistoryWatermark:
		return "slot/epoch is at or below the imported history watermark"
	}
	return "request conflicts with existing record"
}

func dup(old *domain.AttestationRecord) []byte {
	if old == nil {
		return nil
	}
	return append([]byte(nil), old.SigningRoot...)
}

func u64b(v uint64) []byte {
	b := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		b[i] = byte(v)
		v >>= 8
	}
	return b
}
