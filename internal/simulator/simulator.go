// Package simulator 在本地生成确定性的链状态与职责事件，模拟验证者运行过程，
// 不依赖任何真实链数据、外部服务或凭据。
package simulator

import (
	"crypto/sha256"
	"fmt"

	"github.com/lechandonga/validator-slashing-guard-go/internal/domain"
)

// Simulator 生成链推进事件与对应的证明 / 提议职责。
type Simulator struct {
	state      *domain.ChainState
	proposerAt map[uint64]uint64 // slot -> 被选中的验证者索引
	headAtSlot map[uint64][]byte
}

func New(state *domain.ChainState) *Simulator {
	return &Simulator{
		state:      state,
		proposerAt: map[uint64]uint64{},
		headAtSlot: map[uint64][]byte{},
	}
}

// SetProposer 指定某 slot 的出块验证者（本地职责分配）。
func (s *Simulator) SetProposer(slot, validatorIndex uint64) {
	s.proposerAt[slot] = validatorIndex
}

func headRoot(slot uint64) []byte {
	w := sha256.New()
	w.Write([]byte("local/head"))
	w.Write(u64b(slot))
	return w.Sum(nil)
}

// Advance 推进链一个 slot，返回该 slot 的证明职责（如果验证者在委员会中）。
// 本地规则：每 4 个 slot 推进一次 justified epoch，每 8 个推进 finalized。
func (s *Simulator) Advance(validatorIndex uint64, inCommittee bool) (domain.AttestationRequest, bool) {
	h := s.state.Snapshot()
	slot := h.CurrentSlot + 1
	root := headRoot(slot)
	justified := h.JustifiedEpoch
	finalized := h.FinalizedEpoch
	if slot%4 == 0 && domain.EpochOf(slot) > justified {
		justified = domain.EpochOf(slot) - 1
	}
	if slot%8 == 0 && justified > 0 {
		finalized = justified - 1
	}
	s.state.Advance(slot, justified, finalized, root)
	s.headAtSlot[slot] = root
	if !inCommittee {
		return domain.AttestationRequest{}, false
	}
	return domain.AttestationRequest{
		Duty:            domain.Duty{ValidatorIndex: validatorIndex, Slot: slot},
		SourceEpoch:     justified,
		TargetEpoch:     domain.EpochOf(slot),
		BeaconBlockRoot: root,
	}, true
}

// BlockDuty 返回当前 slot 的区块提议职责（若该验证者被选中）。
func (s *Simulator) BlockDuty(validatorIndex uint64) (domain.BlockProposalRequest, bool) {
	h := s.state.Snapshot()
	idx, ok := s.proposerAt[h.CurrentSlot]
	if !ok || idx != validatorIndex {
		return domain.BlockProposalRequest{}, false
	}
	parentRoot := h.HeadRoot
	w := sha256.New()
	w.Write([]byte("local/state"))
	w.Write(parentRoot)
	w.Write(u64b(h.CurrentSlot))
	stateRoot := w.Sum(nil)
	bw := sha256.New()
	bw.Write([]byte("local/body"))
	bw.Write(u64b(h.CurrentSlot))
	return domain.BlockProposalRequest{
		Duty:       domain.Duty{ValidatorIndex: validatorIndex, Slot: h.CurrentSlot},
		ParentRoot: append([]byte(nil), parentRoot...),
		StateRoot:  stateRoot,
		BodyRoot:   bw.Sum(nil),
	}, true
}

// Rollback 把链回退到历史 slot（使用当时生成的头根），用于交织测试。
func (s *Simulator) Rollback(slot, justified, finalized uint64) error {
	root, ok := s.headAtSlot[slot]
	if !ok {
		return fmt.Errorf("simulator: no known head for slot %d", slot)
	}
	s.state.Rollback(slot, justified, finalized, root)
	return nil
}

// AttestationFor 构造与“当前链头一致”的证明职责。
func (s *Simulator) AttestationFor(validatorIndex uint64) domain.AttestationRequest {
	h := s.state.Snapshot()
	return domain.AttestationRequest{
		Duty:            domain.Duty{ValidatorIndex: validatorIndex, Slot: h.CurrentSlot},
		SourceEpoch:     h.JustifiedEpoch,
		TargetEpoch:     domain.EpochOf(h.CurrentSlot),
		BeaconBlockRoot: append([]byte(nil), h.HeadRoot...),
	}
}

// CurrentHead 暴露当前头快照。
func (s *Simulator) CurrentHead() domain.ChainHead { return s.state.Snapshot() }

func u64b(v uint64) []byte {
	b := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		b[i] = byte(v)
		v >>= 8
	}
	return b
}
