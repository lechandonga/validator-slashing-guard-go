// Package signer 实现验证者签名客户端与防罚没准入：
// 每条职责在签署前依次通过“格式 -> 身份 -> 重复 -> 链状态一致性 ->
// 时效 -> 防罚没几何”检查，任何无法判定安全的情形一律拒绝。
package signer

import (
	"crypto/sha256"
	"encoding/binary"
	"sync"

	"github.com/lechandonga/validator-slashing-guard-go/internal/chain"
	"github.com/lechandonga/validator-slashing-guard-go/internal/store"
	"github.com/lechandonga/validator-slashing-guard-go/internal/types"
)

// Signer 持有本地链状态与防罚没记录，对外提供安全签署。
type Signer struct {
	validator types.ValidatorID
	chain     *chain.State
	store     *store.Store
	mu        sync.Mutex // 把“读取记录/状态 -> 判定 -> 固化”串成一个原子临界区
}

// New 构造签名客户端。
func New(validator types.ValidatorID, ch *chain.State, st *store.Store) *Signer {
	return &Signer{validator: validator, chain: ch, store: st}
}

// UnderLock 在与签署完全相同的互斥临界区内执行 fn。
// EIP-3076 导入借此与实时签署互斥，保证并发结论确定、可复现。
func (s *Signer) UnderLock(fn func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fn()
}

// SignAttestation 处理一次证明职责，返回模拟 BLS 签名或可区分原因的拒绝错误。
func (s *Signer) SignAttestation(duty types.AttestationDuty) (types.Signature, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if duty.SigningRoot == (types.Root{}) || duty.BeaconBlockRoot == (types.Root{}) {
		return types.Signature{}, types.Fail(types.ReasonMalformed, "signing root and beacon block root must be present")
	}
	if duty.TargetEpoch != types.EpochOf(duty.Slot) {
		return types.Signature{}, types.Fail(types.ReasonMalformed,
			"target epoch %d does not match slot %d (epoch %d)", duty.TargetEpoch, duty.Slot, types.EpochOf(duty.Slot))
	}
	if duty.SourceEpoch > duty.TargetEpoch {
		return types.Signature{}, types.Fail(types.ReasonMalformed, "source epoch %d greater than target %d", duty.SourceEpoch, duty.TargetEpoch)
	}
	if duty.Validator != s.validator {
		return types.Signature{}, types.Fail(types.ReasonUnknownValidator, "duty validator %s is not the local signer %s", duty.Validator, s.validator)
	}

	for _, rec := range s.store.Attestations() {
		if rec.SigningRoot == duty.SigningRoot {
			return types.Signature{}, types.Fail(types.ReasonDuplicateDuty,
				"attestation with signing root %x at slot %d was already signed", duty.SigningRoot[:4], duty.Slot)
		}
	}

	st := s.chain.Snapshot()
	if duty.Slot > st.CurrentSlot {
		return types.Signature{}, types.Fail(types.ReasonStateMismatch,
			"duty slot %d is in the future, head slot is %d", duty.Slot, st.CurrentSlot)
	}
	canonical, ok := st.BlockRoot(duty.Slot)
	if !ok {
		return types.Signature{}, types.Fail(types.ReasonStateMismatch,
			"no canonical block known at slot %d; cannot attest", duty.Slot)
	}
	if canonical != duty.BeaconBlockRoot {
		return types.Signature{}, types.Fail(types.ReasonStateMismatch,
			"beacon block root for slot %d disagrees with local canonical chain (possible reorg)", duty.Slot)
	}
	if duty.SourceEpoch != st.FinalizedEpoch {
		return types.Signature{}, types.Fail(types.ReasonStateMismatch,
			"attestation source epoch %d disagrees with local finalized epoch %d", duty.SourceEpoch, st.FinalizedEpoch)
	}

	if duty.TargetEpoch <= st.FinalizedEpoch {
		return types.Signature{}, types.Fail(types.ReasonDutyExpired,
			"target epoch %d is already finalized at epoch %d", duty.TargetEpoch, st.FinalizedEpoch)
	}
	if st.CurrentSlot-duty.Slot >= types.SlotsPerEpoch {
		return types.Signature{}, types.Fail(types.ReasonDutyExpired,
			"attestation for slot %d expired at head slot %d", duty.Slot, st.CurrentSlot)
	}

	for _, rec := range s.store.Attestations() {
		if rec.TargetEpoch == duty.TargetEpoch && rec.SigningRoot != duty.SigningRoot {
			return types.Signature{}, types.Fail(types.ReasonDoubleAttestation,
				"target epoch %d already has a distinct attestation (existing source %d)", duty.TargetEpoch, rec.SourceEpoch)
		}
		// 新证明区间被既有记录完全包含：existing.source < new.source && new.target < existing.target。
		if rec.SourceEpoch < duty.SourceEpoch && duty.TargetEpoch < rec.TargetEpoch {
			return types.Signature{}, types.Fail(types.ReasonSurrounded,
				"attestation [%d,%d] is fully contained within signed record [%d,%d]",
				duty.SourceEpoch, duty.TargetEpoch, rec.SourceEpoch, rec.TargetEpoch)
		}
		// 新证明完全包含既有记录同样是罚没条件，安全侧拒绝。
		if duty.SourceEpoch < rec.SourceEpoch && rec.TargetEpoch < duty.TargetEpoch {
			return types.Signature{}, types.Fail(types.ReasonSurrounding,
				"attestation [%d,%d] surrounds previously signed record [%d,%d]",
				duty.SourceEpoch, duty.TargetEpoch, rec.SourceEpoch, rec.TargetEpoch)
		}
	}

	sig := sign(s.validator, "attestation", duty.SigningRoot)
	rec := types.SignedAttestation{
		SourceEpoch:     duty.SourceEpoch,
		TargetEpoch:     duty.TargetEpoch,
		SigningRoot:     duty.SigningRoot,
		BeaconBlockRoot: duty.BeaconBlockRoot,
		Slot:            duty.Slot,
		Signature:       sig,
	}
	// 记录先于“签名离开本进程”固化：AppendAttestation 内完成 fsync。
	if err := s.store.AppendAttestation(rec); err != nil {
		return types.Signature{}, err
	}
	return sig, nil
}

// SignProposal 处理一次区块提议职责。
func (s *Signer) SignProposal(duty types.ProposalDuty) (types.Signature, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if duty.BlockRoot == (types.Root{}) || duty.SigningRoot == (types.Root{}) {
		return types.Signature{}, types.Fail(types.ReasonMalformed, "block root and signing root must be present")
	}
	if duty.Validator != s.validator {
		return types.Signature{}, types.Fail(types.ReasonUnknownValidator, "duty validator %s is not the local signer %s", duty.Validator, s.validator)
	}

	for _, rec := range s.store.Proposals() {
		if rec.SigningRoot == duty.SigningRoot {
			return types.Signature{}, types.Fail(types.ReasonDuplicateDuty,
				"proposal with signing root %x at slot %d was already signed", duty.SigningRoot[:4], duty.Slot)
		}
	}

	st := s.chain.Snapshot()
	if duty.Slot > st.CurrentSlot {
		return types.Signature{}, types.Fail(types.ReasonStateMismatch,
			"proposal slot %d is in the future, head slot is %d", duty.Slot, st.CurrentSlot)
	}
	if duty.Slot < st.CurrentSlot {
		return types.Signature{}, types.Fail(types.ReasonDutyExpired,
			"proposal slot %d is in the past, head slot is %d", duty.Slot, st.CurrentSlot)
	}
	canonical, ok := st.BlockRoot(duty.Slot)
	if !ok || canonical != duty.BlockRoot {
		return types.Signature{}, types.Fail(types.ReasonStateMismatch,
			"block root for slot %d disagrees with local canonical chain (possible reorg)", duty.Slot)
	}

	for _, rec := range s.store.Proposals() {
		if rec.Slot == duty.Slot && rec.BlockRoot != duty.BlockRoot {
			return types.Signature{}, types.Fail(types.ReasonDoubleProposal,
				"slot %d already has a proposal with a different block root", duty.Slot)
		}
	}

	sig := sign(s.validator, "proposal", duty.SigningRoot)
	rec := types.SignedProposal{
		Slot:        duty.Slot,
		BlockRoot:   duty.BlockRoot,
		SigningRoot: duty.SigningRoot,
		Signature:   sig,
	}
	if err := s.store.AppendProposal(rec); err != nil {
		return types.Signature{}, err
	}
	return sig, nil
}

// sign 生成确定性模拟签名：相同验证者与签名根必然得到相同字节，
// 但不代表真实 BLS 密码学，仅用于本地可复现的签署结论。
func sign(validator types.ValidatorID, domain string, signingRoot types.Root) types.Signature {
	var sig types.Signature
	for chunk := uint32(0); chunk < 3; chunk++ {
		h := sha256.New()
		h.Write(validator[:])
		h.Write([]byte(domain))
		var cb [4]byte
		binary.LittleEndian.PutUint32(cb[:], chunk)
		h.Write(cb[:])
		h.Write(signingRoot[:])
		copy(sig[chunk*32:], h.Sum(nil))
	}
	return sig
}
