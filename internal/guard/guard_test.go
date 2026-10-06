package guard_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/lechandonga/validator-slashing-guard-go/internal/domain"
	"github.com/lechandonga/validator-slashing-guard-go/internal/guard"
	"github.com/lechandonga/validator-slashing-guard-go/internal/store"
)

var gvr = []byte("local-genesis-validators-root-0001")

func beaconPubkey(b byte) []byte {
	k := make([]byte, 48)
	for i := range k {
		k[i] = b
	}
	return k
}

func newValidator(index uint64, id byte) *guard.Validator {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return guard.NewValidator(index, beaconPubkey(id), priv)
}

type env struct {
	t      *testing.T
	state  *domain.ChainState
	store  *store.Store
	client *guard.Client
	vals   map[uint64]*guard.Validator
	dir    string
}

func setup(t *testing.T, indices ...uint64) *env {
	t.Helper()
	dir := t.TempDir()
	state := domain.NewChainState(gvr, []byte{1, 0, 0, 0}, []byte("genesis-head"))
	st, err := store.Open(filepath.Join(dir, "records.json"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if len(indices) == 0 {
		indices = []uint64{1}
	}
	vals := map[uint64]*guard.Validator{}
	var list []*guard.Validator
	for i, index := range indices {
		v := newValidator(index, byte(0xA0+i))
		vals[index] = v
		list = append(list, v)
	}
	return &env{t: t, state: state, store: st,
		client: guard.NewClient(state, st, list...), vals: vals, dir: dir}
}

// advanceTo 推进到指定 slot，返回与链头一致、归属 validator 的证明职责。
func (e *env) advanceTo(validator, slot, justified uint64) domain.AttestationRequest {
	h := e.state.Snapshot()
	for h.CurrentSlot < slot {
		next := h.CurrentSlot + 1
		root := fmt.Appendf(nil, "head@%d", next)
		e.state.Advance(next, justified, justified-1, root)
		h = e.state.Snapshot()
	}
	return domain.AttestationRequest{
		Duty:            domain.Duty{ValidatorIndex: validator, Slot: slot},
		BeaconPublicKey: append([]byte(nil), e.vals[validator].BeaconPubKey...),
		SourceEpoch:     justified,
		TargetEpoch:     domain.EpochOf(slot),
		BeaconBlockRoot: append([]byte(nil), h.HeadRoot...),
	}
}

func reason(err error) string {
	var ge *domain.GuardError
	if errors.As(err, &ge) {
		return ge.Reason
	}
	return ""
}

func bytes32(s string) []byte {
	b := []byte(s)
	if len(b) >= 32 {
		return b[:32]
	}
	return append(b, make([]byte, 32-len(b))...)
}

func TestAttestationAdmissionReasons(t *testing.T) {
	t.Log("业务: 证明签名准入 —— 正常通过及各可区分拒绝原因")
	e := setup(t)
	duty := e.advanceTo(1, 8, 1)

	cases := []struct {
		name   string
		mutate func(*domain.AttestationRequest)
		want   string
	}{
		{"链头不一致被拒", func(a *domain.AttestationRequest) { a.BeaconBlockRoot = []byte("other-head-32-bytes-0000000000000") }, domain.ReasonStateMismatch},
		{"justified epoch 不一致被拒", func(a *domain.AttestationRequest) { a.SourceEpoch = 0 }, domain.ReasonStateMismatch},
		{"未来职责被拒", func(a *domain.AttestationRequest) {
			a.Slot = 9
			a.TargetEpoch = domain.EpochOf(9)
		}, domain.ReasonDutyFuture},
		{"空区块根非法", func(a *domain.AttestationRequest) { a.BeaconBlockRoot = nil }, domain.ReasonInvalidRequest},
		{"source>target 非法", func(a *domain.AttestationRequest) { a.SourceEpoch = 5 }, domain.ReasonInvalidRequest},
	}

	if _, err := e.client.SignAttestation(duty); err != nil {
		t.Fatalf("合法证明必须可签署: %v", err)
	}
	t.Log("用例[合法证明可签署] 通过，记录 1 条")

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := duty
			tc.mutate(&req)
			_, err := e.client.SignAttestation(req)
			if got := reason(err); got != tc.want {
				t.Fatalf("want %s, got %v", tc.want, err)
			}
			atts, _ := e.store.Snapshot()
			if len(atts) != 1 {
				t.Fatalf("拒绝不得污染记录，atts=%d", len(atts))
			}
			t.Logf("用例[%s] 拒绝原因=%s，记录数不变", tc.name, reason(err))
		})
	}

	t.Run("过期职责被拒", func(t *testing.T) {
		e2 := setup(t)
		req := e2.advanceTo(1, 7, 0)
		if _, err := e2.client.SignAttestation(req); err != nil {
			t.Fatalf("sign at slot 7: %v", err)
		}
		e2.state.Advance(8, 1, 0, []byte("head@8"))
		if _, err := e2.client.SignAttestation(req); reason(err) != domain.ReasonDutyExpired {
			t.Fatalf("want DUTY_EXPIRED, got %v", err)
		}
		t.Log("用例: 链推进后重提旧 slot 职责 -> DUTY_EXPIRED")
	})
}

func TestIdentityMismatchAndUnknownValidator(t *testing.T) {
	t.Log("业务: 多身份归属 —— 身份不匹配/未知身份明确拒绝且不留任何记录")
	e := setup(t, 1, 2)
	duty := e.advanceTo(1, 8, 1)

	imposter := duty
	imposter.BeaconPublicKey = append([]byte(nil), e.vals[2].BeaconPubKey...)
	if _, err := e.client.SignAttestation(imposter); reason(err) != domain.ReasonIdentityMismatch {
		t.Fatalf("want IDENTITY_MISMATCH, got %v", err)
	}

	noKey := duty
	noKey.BeaconPublicKey = nil
	if _, err := e.client.SignAttestation(noKey); reason(err) != domain.ReasonIdentityMismatch {
		t.Fatalf("missing pubkey want IDENTITY_MISMATCH, got %v", err)
	}

	unknown := duty
	unknown.ValidatorIndex = 99
	unknown.BeaconPublicKey = beaconPubkey(0x99)
	if _, err := e.client.SignAttestation(unknown); reason(err) != domain.ReasonUnknownValidator {
		t.Fatalf("want UNKNOWN_VALIDATOR, got %v", err)
	}

	block := domain.BlockProposalRequest{
		Duty:            domain.Duty{ValidatorIndex: 1, Slot: 8},
		BeaconPublicKey: append([]byte(nil), e.vals[2].BeaconPubKey...),
		ParentRoot:      []byte("parent-root-32-bytes-0000000000000000000"),
		StateRoot:       []byte("state-root-32-bytes-000000000000000000000"),
		BodyRoot:        []byte("body-root-32-bytes-0000000000000000000000"),
	}
	if _, err := e.client.SignBlock(block); reason(err) != domain.ReasonIdentityMismatch {
		t.Fatalf("block want IDENTITY_MISMATCH, got %v", err)
	}

	atts, blocks := e.store.Snapshot()
	if len(atts) != 0 || len(blocks) != 0 {
		t.Fatalf("任何身份下都不得留下记录: atts=%d blocks=%d", len(atts), len(blocks))
	}
	t.Log("用例: 公钥错配/缺公钥 -> IDENTITY_MISMATCH；未托管索引 -> UNKNOWN_VALIDATOR；记录零污染")
}

func TestMultiValidatorRecordIsolation(t *testing.T) {
	t.Log("业务: 多身份记录隔离 —— 同 slot/同 target 不同身份各自判定，不串用")
	e := setup(t, 1, 2)
	d1 := e.advanceTo(1, 8, 1)
	if _, err := e.client.SignAttestation(d1); err != nil {
		t.Fatalf("v1 sign: %v", err)
	}

	// 身份 2 在完全相同的 target epoch 签不同内容：不得被身份 1 的记录判为 double vote。
	d2 := e.advanceTo(2, 8, 1)
	if _, err := e.client.SignAttestation(d2); err != nil {
		t.Fatalf("v2 sign at same target must be allowed: %v", err)
	}

	// 身份 2 自己再签同 target 的另一内容 -> DOUBLE_VOTE（用纯判定函数绕开链头准入）。
	d2Double := d2
	d2Double.BeaconBlockRoot = bytes32("other-chain-head-root-32-bytes!xy")
	diffHead := e.state.Snapshot()
	diffHead.HeadRoot = d2Double.BeaconBlockRoot
	attsNow, _ := e.store.Snapshot()
	if _, r := guard.FindAttestationConflict(2, d2Double.SourceEpoch, d2Double.TargetEpoch,
		d2Double.BeaconBlockRoot, d2Double.SigningRoot(diffHead), attsNow); r != domain.ReasonDoubleVote {
		t.Fatalf("v2 same target diff root want DOUBLE_VOTE, got %q", r)
	}

	// 区块：身份 1 与身份 2 可以在同一 slot 各签各的；身份 1 自己不能签第二个。
	mkBlock := func(val uint64, tag byte) domain.BlockProposalRequest {
		stateRoot := make([]byte, 32)
		stateRoot[0] = tag
		return domain.BlockProposalRequest{
			Duty:            domain.Duty{ValidatorIndex: val, Slot: 8},
			BeaconPublicKey: append([]byte(nil), e.vals[val].BeaconPubKey...),
			ParentRoot:      bytes32("parent-root-32-bytes-000000000"),
			StateRoot:       stateRoot,
			BodyRoot:        bytes32("body-root-32-bytes-0000000000000"),
		}
	}
	if _, err := e.client.SignBlock(mkBlock(1, 1)); err != nil {
		t.Fatalf("v1 block: %v", err)
	}
	if _, err := e.client.SignBlock(mkBlock(2, 2)); err != nil {
		t.Fatalf("v2 block at same slot must be allowed: %v", err)
	}
	if _, err := e.client.SignBlock(mkBlock(1, 9)); reason(err) != domain.ReasonDuplicateBlockSlot {
		t.Fatalf("v1 second block want DUPLICATE_BLOCK_SLOT, got %v", err)
	}

	atts, blocks := e.store.Snapshot()
	if len(atts) != 2 {
		t.Fatalf("atts=%d want 2 (one per validator)", len(atts))
	}
	if len(blocks) != 2 {
		t.Fatalf("blocks=%d want 2 (one per validator)", len(blocks))
	}
	t.Log("用例: 证明/区块判定按身份隔离；同 target 跨身份允许、同身份冲突拒绝")
}

func TestDuplicateDutyConcurrentSingleSuccess(t *testing.T) {
	t.Log("业务: 同一证明职责并发触发 —— 恰好一次有效签名，其余 DUPLICATE_DUTY")
	e := setup(t)
	duty := e.advanceTo(1, 8, 1)

	const n = 64
	var wg sync.WaitGroup
	var success, duplicate, other int64
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := e.client.SignAttestation(duty)
			switch {
			case err == nil:
				atomic.AddInt64(&success, 1)
			case reason(err) == domain.ReasonDuplicateDuty:
				atomic.AddInt64(&duplicate, 1)
			default:
				atomic.AddInt64(&other, 1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if success != 1 || duplicate != n-1 || other != 0 {
		t.Fatalf("success=%d duplicate=%d other=%d", success, duplicate, other)
	}
	atts, _ := e.store.Snapshot()
	if len(atts) != 1 {
		t.Fatalf("records=%d, want 1", len(atts))
	}
	t.Logf("用例: %d 个并发 -> 成功 1, 重复拒绝 %d, 记录仅 1 条", n, n-1)
}

func TestDoubleVoteAndSurround(t *testing.T) {
	t.Log("业务: 防罚没判定 —— double vote 与 surround vote 均拒绝且不污染记录")
	e := setup(t)

	first := e.advanceTo(1, 16, 0) // slot 16 => epoch 2
	first.SourceEpoch = 0
	h := e.state.Snapshot()
	first.BeaconBlockRoot = h.HeadRoot
	if _, err := e.client.SignAttestation(first); err != nil {
		t.Fatalf("first sign: %v", err)
	}

	atts, _ := e.store.Snapshot()
	diffRoot := bytes32("different-block-root-32-bytes!!!")
	if _, r := guard.FindAttestationConflict(1, 0, 2, diffRoot,
		domain.AttestationRequest{
			Duty:        domain.Duty{Slot: 16, ValidatorIndex: 1},
			SourceEpoch: 0, TargetEpoch: 2, BeaconBlockRoot: diffRoot,
		}.SigningRoot(h), atts); r != domain.ReasonDoubleVote {
		t.Fatalf("want DOUBLE_VOTE, got %q", r)
	}
	t.Log("用例: 同 target epoch 不同内容 -> DOUBLE_VOTE")

	e2 := setup(t)
	big := e2.advanceTo(1, 32, 0) // epoch 4
	big.SourceEpoch = 0
	if _, err := e2.client.SignAttestation(big); err != nil {
		t.Fatalf("big sign: %v", err)
	}
	atts2, _ := e2.store.Snapshot()
	innerRoot := bytes32("inner-head-32-bytes-000000000000")
	if _, r := guard.FindAttestationConflict(1, 1, 3, innerRoot,
		domain.AttestationRequest{
			Duty:        domain.Duty{Slot: 30, ValidatorIndex: 1},
			SourceEpoch: 1, TargetEpoch: 3, BeaconBlockRoot: innerRoot,
		}.SigningRoot(e2.state.Snapshot()), atts2); r != domain.ReasonSurroundVote {
		t.Fatalf("want SURROUND_VOTE, got %q", r)
	}

	// 反向 surround：已有小区间 (1,3)，再来大区间 (0,4) 同样拒绝。
	e3 := setup(t)
	small := e3.advanceTo(1, 24, 1) // epoch 3
	small.SourceEpoch = 1
	small.TargetEpoch = 3
	if _, err := e3.client.SignAttestation(small); err != nil {
		t.Fatalf("small sign: %v", err)
	}
	atts3, _ := e3.store.Snapshot()
	largeRoot := bytes32("large-head-32-bytes-000000000000")
	if _, r := guard.FindAttestationConflict(1, 0, 4, largeRoot,
		domain.AttestationRequest{
			Duty:        domain.Duty{Slot: 32, ValidatorIndex: 1},
			SourceEpoch: 0, TargetEpoch: 4, BeaconBlockRoot: largeRoot,
		}.SigningRoot(e3.state.Snapshot()), atts3); r != domain.ReasonSurroundVote {
		t.Fatalf("want reverse SURROUND_VOTE, got %q", r)
	}
	t.Log("用例: 新区间被既有记录完全包含 -> SURROUND_VOTE；反向包含同样拒绝")
}

func TestBlockProposalNoDoubleSign(t *testing.T) {
	t.Log("业务: 区块提议 —— 同 slot 不重复签署")
	e := setup(t)
	e.advanceTo(1, 10, 1)
	block := domain.BlockProposalRequest{
		Duty:            domain.Duty{ValidatorIndex: 1, Slot: 10},
		BeaconPublicKey: append([]byte(nil), e.vals[1].BeaconPubKey...),
		ParentRoot:      bytes32("parent-root-32-bytes-000000000"),
		StateRoot:       bytes32("state-root-32-bytes-0000000000000"),
		BodyRoot:        bytes32("body-root-32-bytes-00000000000000"),
	}
	if _, err := e.client.SignBlock(block); err != nil {
		t.Fatalf("first block sign: %v", err)
	}
	if _, err := e.client.SignBlock(block); reason(err) != domain.ReasonDuplicateDuty {
		t.Fatalf("identical block: want DUPLICATE_DUTY, got %v", err)
	}
	t.Log("用例: 同一区块重复 -> DUPLICATE_DUTY")

	var success, dup int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := e.client.SignBlock(block); err == nil {
				atomic.AddInt64(&success, 1)
			} else if reason(err) == domain.ReasonDuplicateDuty {
				atomic.AddInt64(&dup, 1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if success != 0 {
		t.Fatalf("expected 0 new successes for already-signed block, got %d", success)
	}
	t.Logf("用例: 已签区块 %d 并发 -> 全部重复拒绝 (dup=%d)", 32, dup)
}

func TestCrashRestartConsistency(t *testing.T) {
	t.Log("业务: 崩溃恢复 —— 提交点前后崩溃，记录与结论一致")
	e := setup(t)
	duty := e.advanceTo(1, 8, 1)

	e.store.SetCrashHook(func(phase string) bool { return phase == "before_rename" })
	if err := signErr(e.client, duty); !store.SimulatedCrash(err) {
		t.Fatalf("want simulated crash, got %v", err)
	}
	e.store.SetCrashHook(nil)

	st2, err := store.Open(filepath.Join(e.dir, "records.json"))
	if err != nil {
		t.Fatal(err)
	}
	atts, _ := st2.Snapshot()
	if len(atts) != 0 {
		t.Fatalf("record must not exist before rename, got %d", len(atts))
	}
	client2 := guard.NewClient(e.state, st2, e.vals[1])
	if _, err := client2.SignAttestation(duty); err != nil {
		t.Fatalf("re-sign after pre-rename crash: %v", err)
	}
	atts, _ = st2.Snapshot()
	if len(atts) != 1 {
		t.Fatalf("want 1 record, got %d", len(atts))
	}

	e2 := setup(t)
	d2 := e2.advanceTo(1, 8, 1)
	e2.store.SetCrashHook(func(phase string) bool { return phase == "after_rename" })
	err = signErr(e2.client, d2)
	if !store.SimulatedCrash(err) {
		t.Fatalf("want post-rename crash, got %v", err)
	}
	st3, err := store.Open(filepath.Join(e2.dir, "records.json"))
	if err != nil {
		t.Fatal(err)
	}
	atts3, _ := st3.Snapshot()
	if len(atts3) != 1 {
		t.Fatalf("committed record must survive crash, got %d", len(atts3))
	}
	client3 := guard.NewClient(e2.state, st3, e2.vals[1])
	if _, err := client3.SignAttestation(d2); reason(err) != domain.ReasonDuplicateDuty {
		t.Fatalf("post-crash re-sign must be DUPLICATE_DUTY, got %v", err)
	}
	t.Log("用例: rename 前崩溃无记录可重签；rename 后崩溃记录在、重签被识别为重复")
}

func TestRollbackPreservesRecords(t *testing.T) {
	t.Log("业务: 链状态回退 —— 历史记录不撤销，新判定基于回退后状态")
	e := setup(t)
	duty := e.advanceTo(1, 8, 1)
	if _, err := e.client.SignAttestation(duty); err != nil {
		t.Fatal(err)
	}
	e.state.Rollback(4, 0, 0, []byte("head@4"))
	atts, _ := e.store.Snapshot()
	if len(atts) != 1 {
		t.Fatalf("records revoked by rollback: %d", len(atts))
	}
	if _, err := e.client.SignAttestation(duty); reason(err) != domain.ReasonDutyFuture {
		t.Fatalf("want DUTY_FUTURE after rollback, got %v", err)
	}
	t.Log("用例: 回退后记录仍为 1 条；旧职责基于回退后状态以 DUTY_FUTURE 拒绝")
}

func signErr(c *guard.Client, a domain.AttestationRequest) error {
	_, err := c.SignAttestation(a)
	return err
}
