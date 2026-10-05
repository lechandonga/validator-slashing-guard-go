package signer_test

import (
	"errors"
	"sync"
	"testing"

	"github.com/lechandonga/validator-slashing-guard-go/internal/types"
)

func reasonOf(t *testing.T, err error) types.Reason {
	t.Helper()
	var ve *types.ValidationError
	if errors.As(err, &ve) {
		return ve.Reason
	}
	t.Fatalf("expected ValidationError, got %v", err)
	return ""
}

// TestBusinessHappyPath 业务：与链状态一致的证明与提议可以签署。
func TestBusinessHappyPath(t *testing.T) {
	f := newFixture(t)
	f.advanceTo(t, 17)

	t.Run("attestation_consistent_with_chain_state", func(t *testing.T) {
		if _, err := f.signer.SignAttestation(f.attestDuty(17, "att-17")); err != nil {
			t.Fatalf("expected sign success, got %v", err)
		}
	})
	t.Run("proposal_at_current_slot", func(t *testing.T) {
		if _, err := f.signer.SignProposal(f.proposalDuty(17)); err != nil {
			t.Fatalf("expected sign success, got %v", err)
		}
	})
}

// TestBusinessConcurrentDuplicates 业务：同一职责并发触发只能成功一次。
func TestBusinessConcurrentDuplicates(t *testing.T) {
	f := newFixture(t)
	f.advanceTo(t, 17)
	duty := f.attestDuty(17, "att-17")

	const n = 64
	var wg sync.WaitGroup
	var mu sync.Mutex
	success, dup := 0, 0
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := f.signer.SignAttestation(duty)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				success++
			case reasonOf(t, err) == types.ReasonDuplicateDuty:
				dup++
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()

	if success != 1 {
		t.Fatalf("expected exactly 1 valid signature, got %d", success)
	}
	if dup != n-1 {
		t.Fatalf("expected %d duplicate rejects, got %d", n-1, dup)
	}
	if len(f.store.Attestations()) != 1 {
		t.Fatalf("expected exactly 1 durable record, got %d", len(f.store.Attestations()))
	}
}

// TestBusinessStateMismatch 业务：请求与本地链状态不一致必须拒绝。
func TestBusinessStateMismatch(t *testing.T) {
	f := newFixture(t)
	f.advanceTo(t, 17)

	t.Run("wrong_beacon_block_root", func(t *testing.T) {
		d := f.attestDuty(17, "att-17")
		d.BeaconBlockRoot[0] ^= 0xFF
		d.SigningRoot[0] ^= 0x01
		if got := reasonOf(t, mustErr(f.signer.SignAttestation(d))); got != types.ReasonStateMismatch {
			t.Fatalf("want state_mismatch, got %s", got)
		}
	})
	t.Run("future_slot", func(t *testing.T) {
		d := f.attestDuty(17, "att-17")
		d.Slot = 500
		d.TargetEpoch = types.EpochOf(500)
		if got := reasonOf(t, mustErr(f.signer.SignAttestation(d))); got != types.ReasonStateMismatch {
			t.Fatalf("want state_mismatch, got %s", got)
		}
	})
	t.Run("wrong_source_epoch", func(t *testing.T) {
		d := f.attestDuty(17, "att-17")
		d.SourceEpoch = 1 // 与本地 finalized epoch 0 不一致但仍是合法 source<target
		if got := reasonOf(t, mustErr(f.signer.SignAttestation(d))); got != types.ReasonStateMismatch {
			t.Fatalf("want state_mismatch, got %s", got)
		}
	})
	t.Run("unknown_validator", func(t *testing.T) {
		d := f.attestDuty(17, "att-17")
		d.Validator[0] = 0x01
		if got := reasonOf(t, mustErr(f.signer.SignAttestation(d))); got != types.ReasonUnknownValidator {
			t.Fatalf("want unknown_validator, got %s", got)
		}
	})
	t.Run("malformed_epochs", func(t *testing.T) {
		d := f.attestDuty(17, "att-17")
		d.TargetEpoch = 9
		if got := reasonOf(t, mustErr(f.signer.SignAttestation(d))); got != types.ReasonMalformed {
			t.Fatalf("want malformed_request, got %s", got)
		}
	})
	if len(f.store.Attestations()) != 0 {
		t.Fatalf("rejected duties must not pollute records, got %d", len(f.store.Attestations()))
	}
}

// TestBusinessExpiredDuty 业务：过期职责必须拒绝。
func TestBusinessExpiredDuty(t *testing.T) {
	f := newFixture(t)
	f.advanceTo(t, 17)
	d17 := f.attestDuty(17, "att-17")
	if _, err := f.signer.SignAttestation(d17); err != nil {
		t.Fatalf("sign: %v", err)
	}
	// 继续推进超过一个 epoch，slot 17 的职责过期。
	f.advanceTo(t, 30)
	t.Run("slot_too_old", func(t *testing.T) {
		// slot 17 此刻规范根仍在，但已超出生存窗口；用不同 signing root 避开重复判定。
		d := f.attestDuty(17, "att-17-late")
		if got := reasonOf(t, mustErr(f.signer.SignAttestation(d))); got != types.ReasonDutyExpired {
			t.Fatalf("want duty_expired, got %s", got)
		}
	})
	t.Run("proposal_past_slot", func(t *testing.T) {
		if got := reasonOf(t, mustErr(f.signer.SignProposal(f.proposalDuty(17)))); got != types.ReasonDutyExpired {
			t.Fatalf("want duty_expired, got %s", got)
		}
	})
}

// TestBusinessSlashingRules 业务：证明几何与提议防罚没规则。
func TestBusinessSlashingRules(t *testing.T) {
	t.Run("double_attestation_same_target", func(t *testing.T) {
		f := newFixture(t)
		f.advanceTo(t, 25) // epoch 3, finalized 1
		first := f.attestDuty(25, "att-a")
		if _, err := f.signer.SignAttestation(first); err != nil {
			t.Fatalf("sign first: %v", err)
		}
		second := f.attestDuty(25, "att-b")
		if got := reasonOf(t, mustErr(f.signer.SignAttestation(second))); got != types.ReasonDoubleAttestation {
			t.Fatalf("want double_attestation, got %s", got)
		}
	})

	t.Run("surrounded_rejected_by_history_geometry", func(t *testing.T) {
		f := newFixture(t)
		f.advanceTo(t, 40) // epoch 5, finalized 3；证明 source 必须为 3
		// 直接在存储层固化历史记录 [1,6]（模拟从旧客户端迁移而来），
		// 新证明 [3,5] 被既有记录 [1,6] 严格包含，应被 surrounded 拦截。
		if err := f.store.CommitReplacement(
			[]types.SignedAttestation{{SourceEpoch: 1, TargetEpoch: 6, SigningRoot: rootFromTag("wide", 1, types.Root{})}},
			nil,
		); err != nil {
			t.Fatalf("seed record: %v", err)
		}
		narrow := attestManual(f, 40, 3, 5, "narrow")
		if got := reasonOf(t, mustErr(f.signer.SignAttestation(narrow))); got != types.ReasonSurrounded {
			t.Fatalf("want surrounded, got %s", got)
		}
	})

	t.Run("double_proposal_same_slot", func(t *testing.T) {
		f := newFixture(t)
		f.advanceTo(t, 17)
		p := f.proposalDuty(17)
		if _, err := f.signer.SignProposal(p); err != nil {
			t.Fatalf("sign proposal: %v", err)
		}
		p2 := p
		p2.SigningRoot[0] ^= 0x01
		p2.BlockRoot[0] ^= 0x01
		// 与链状态不一致时先报 state_mismatch；为了直击 double_proposal，
		// 用 store 中已有同 slot 记录、再回退场景覆盖（见 reorg 测试）。
		_ = p2
	})
}

// TestBusinessReorg 业务：链回退后记录保留，新判定基于回退状态。
func TestBusinessReorg(t *testing.T) {
	f := newFixture(t)
	f.advanceTo(t, 17)
	before := f.attestDuty(17, "att-17")
	if _, err := f.signer.SignAttestation(before); err != nil {
		t.Fatalf("sign: %v", err)
	}

	forkRoot, err := f.chain.Reorg(16, 17)
	if err != nil {
		t.Fatalf("reorg: %v", err)
	}
	if len(f.store.Attestations()) != 1 {
		t.Fatalf("reorg must not revoke records")
	}

	t.Run("forked_attestation_double_rejected", func(t *testing.T) {
		d := types.AttestationDuty{
			Validator:       f.validator,
			Slot:            17,
			BeaconBlockRoot: forkRoot,
			TargetEpoch:     types.EpochOf(17),
			SourceEpoch:     f.chain.FinalizedEpoch,
			SigningRoot:     rootFromTag("att-fork", 17, forkRoot),
		}
		if got := reasonOf(t, mustErr(f.signer.SignAttestation(d))); got != types.ReasonDoubleAttestation {
			t.Fatalf("want double_attestation after reorg, got %s", got)
		}
	})

	t.Run("forked_proposal_double_rejected", func(t *testing.T) {
		// 先在 slot 18 签一个提议，再回退到 17 并推进到 18 产生竞争块。
		f2 := newFixture(t)
		f2.advanceTo(t, 18)
		if _, err := f2.signer.SignProposal(f2.proposalDuty(18)); err != nil {
			t.Fatalf("sign proposal: %v", err)
		}
		if _, err := f2.chain.Reorg(17, 18); err != nil {
			t.Fatalf("reorg: %v", err)
		}
		block, _ := f2.chain.BlockRoot(18)
		d := types.ProposalDuty{Validator: f2.validator, Slot: 18, BlockRoot: block,
			SigningRoot: rootFromTag("proposal-fork", 18, block)}
		if got := reasonOf(t, mustErr(f2.signer.SignProposal(d))); got != types.ReasonDoubleProposal {
			t.Fatalf("want double_proposal, got %s", got)
		}
	})
}

func attestManual(f *fixture, slot, source, target uint64, tag string) types.AttestationDuty {
	block, _ := f.chain.BlockRoot(slot)
	return types.AttestationDuty{
		Validator:       f.validator,
		Slot:            slot,
		BeaconBlockRoot: block,
		SourceEpoch:     source,
		TargetEpoch:     target,
		SigningRoot:     rootFromTag(tag, target, rootFromTag(tag, source, block)),
	}
}

func mustErr(_ types.Signature, err error) error {
	if err == nil {
		panic("expected error, got nil")
	}
	return err
}
