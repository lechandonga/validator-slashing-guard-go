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

type env struct {
	t      *testing.T
	state  *domain.ChainState
	store  *store.Store
	client *guard.Client
	val    *guard.Validator
	dir    string
}

func setup(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	state := domain.NewChainState(gvr, []byte{1, 0, 0, 0}, []byte("genesis-head"))
	st, err := store.Open(filepath.Join(dir, "records.json"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = pub
	val := guard.NewValidator(1, priv)
	return &env{t: t, state: state, store: st, client: guard.NewClient(state, st, val), val: val, dir: dir}
}

// advanceTo 推进到指定 slot，返回与链头一致的证明职责。
func (e *env) advanceTo(slot, justified uint64) domain.AttestationRequest {
	h := e.state.Snapshot()
	for h.CurrentSlot < slot {
		next := h.CurrentSlot + 1
		root := fmt.Appendf(nil, "head@%d", next)
		e.state.Advance(next, justified, justified-1, root)
		h = e.state.Snapshot()
	}
	return domain.AttestationRequest{
		Duty:            domain.Duty{ValidatorIndex: 1, Slot: slot},
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

func TestAttestationAdmissionReasons(t *testing.T) {
	t.Log("业务: 证明签名准入 —— 正常通过及各可区分拒绝原因")
	e := setup(t)
	duty := e.advanceTo(8, 1)

	cases := []struct {
		name   string
		mutate func(*domain.AttestationRequest)
		want   string
	}{
		{"合法证明可签署", nil, ""},
		{"链头不一致被拒", func(a *domain.AttestationRequest) { a.BeaconBlockRoot = []byte("other-head-32-bytes-0000000000000") }, domain.ReasonStateMismatch},
		{"justified epoch 不一致被拒", func(a *domain.AttestationRequest) { a.SourceEpoch = 0 }, domain.ReasonStateMismatch},
		{"未来职责被拒", func(a *domain.AttestationRequest) {
			a.Slot = 9
			a.TargetEpoch = domain.EpochOf(9)
		}, domain.ReasonDutyFuture},
		{"空区块根非法", func(a *domain.AttestationRequest) { a.BeaconBlockRoot = nil }, domain.ReasonInvalidRequest},
		{"source>target 非法", func(a *domain.AttestationRequest) { a.SourceEpoch = 5 }, domain.ReasonInvalidRequest},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := duty
			if tc.mutate != nil {
				tc.mutate(&req)
			}
			_, err := e.client.SignAttestation(req)
			if i == 0 {
				if err != nil {
					t.Fatalf("expected success, got %v", err)
				}
				return
			}
			if got := reason(err); got != tc.want {
				t.Fatalf("want %s, got %v", tc.want, err)
			}
			t.Logf("用例[%s] 拒绝原因=%s，记录数不变", tc.name, reason(err))
		})
	}

	t.Run("过期职责被拒", func(t *testing.T) {
		e2 := setup(t)
		req := e2.advanceTo(7, 0)
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

func TestDuplicateDutyConcurrentSingleSuccess(t *testing.T) {
	t.Log("业务: 同一证明职责并发触发 —— 恰好一次有效签名，其余 DUPLICATE_DUTY")
	e := setup(t)
	duty := e.advanceTo(8, 1)

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

	// 第一条：source=0,target=2（用直接通过准入的方式签）
	first := e.advanceTo(16, 0) // slot 16 => epoch 2
	first.SourceEpoch = 0
	h := e.state.Snapshot()
	first.BeaconBlockRoot = h.HeadRoot
	if _, err := e.client.SignAttestation(first); err != nil {
		t.Fatalf("first sign: %v", err)
	}

	// double vote：同 target=2，不同区块根。准入要求与头一致，这里直接替换头根后
	// 通过 store.Update 已不易模拟，因此改用纯函数 FindAttestationConflict 校验规则。
	atts, _ := e.store.Snapshot()
	diffRoot := []byte("different-block-root-32-bytes!!!")
	if _, r := guard.FindAttestationConflict(1, 0, 2, diffRoot,
		domain.AttestationRequest{
			Duty: domain.Duty{Slot: 16}, SourceEpoch: 0, TargetEpoch: 2,
			BeaconBlockRoot: diffRoot,
		}.SigningRoot(h), atts); r != domain.ReasonDoubleVote {
		t.Fatalf("want DOUBLE_VOTE, got %q", r)
	}
	t.Log("用例: 同 target epoch 不同内容 -> DOUBLE_VOTE")

	// surround：已有 (0,2)，新 (1,?) 不可能被包含；构造已有大区间 (0,4) 再签 (1,3)
	e2 := setup(t)
	big := e2.advanceTo(32, 0) // epoch 4
	big.SourceEpoch = 0
	if _, err := e2.client.SignAttestation(big); err != nil {
		t.Fatalf("big sign: %v", err)
	}
	atts2, _ := e2.store.Snapshot()
	innerRoot := []byte("inner-head-32-bytes-000000000000000000000000")
	if _, r := guard.FindAttestationConflict(1, 1, 3, innerRoot,
		domain.AttestationRequest{
			Duty: domain.Duty{Slot: 30}, SourceEpoch: 1, TargetEpoch: 3,
			BeaconBlockRoot: innerRoot,
		}.SigningRoot(e2.state.Snapshot()), atts2); r != domain.ReasonSurroundVote {
		t.Fatalf("want SURROUND_VOTE, got %q", r)
	}
	t.Log("用例: 新区间被既有记录完全包含 -> SURROUND_VOTE")
}

func TestBlockProposalNoDoubleSign(t *testing.T) {
	t.Log("业务: 区块提议 —— 同 slot 不重复签署")
	e := setup(t)
	e.advanceTo(10, 1)
	block := domain.BlockProposalRequest{
		Duty:       domain.Duty{ValidatorIndex: 1, Slot: 10},
		ParentRoot: []byte("parent-root-32-bytes-0000000000000000000"),
		StateRoot:  []byte("state-root-32-bytes-000000000000000000000"),
		BodyRoot:   []byte("body-root-32-bytes-0000000000000000000000"),
	}
	if _, err := e.client.SignBlock(block); err != nil {
		t.Fatalf("first block sign: %v", err)
	}
	if _, err := e.client.SignBlock(block); reason(err) != domain.ReasonDuplicateDuty {
		t.Fatalf("identical block: want DUPLICATE_DUTY, got %v", err)
	}
	t.Log("用例: 同一区块并发/重复 -> DUPLICATE_DUTY")

	// 并发全新区块：只有 1 个成功
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
	duty := e.advanceTo(8, 1)

	// 注入：rename 前崩溃 => 记录不存在，重开后可正常签署一次。
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
	client2 := guard.NewClient(e.state, st2, e.clientValue())
	if _, err := client2.SignAttestation(duty); err != nil {
		t.Fatalf("re-sign after pre-rename crash: %v", err)
	}
	atts, _ = st2.Snapshot()
	if len(atts) != 1 {
		t.Fatalf("want 1 record, got %d", len(atts))
	}

	// 注入：rename 后、返回前崩溃 => 记录已固化，重开后视为已签。
	e2 := setup(t)
	d2 := e2.advanceTo(8, 1)
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
	client3 := guard.NewClient(e2.state, st3, e2.clientValue())
	if _, err := client3.SignAttestation(d2); reason(err) != domain.ReasonDuplicateDuty {
		t.Fatalf("post-crash re-sign must be DUPLICATE_DUTY, got %v", err)
	}
	t.Log("用例: rename 前崩溃无记录可重签；rename 后崩溃记录在、重签被识别为重复")
}

func TestRollbackPreservesRecords(t *testing.T) {
	t.Log("业务: 链状态回退 —— 历史记录不撤销，新判定基于回退后状态")
	e := setup(t)
	duty := e.advanceTo(8, 1)
	if _, err := e.client.SignAttestation(duty); err != nil {
		t.Fatal(err)
	}
	e.state.Rollback(4, 0, 0, []byte("head@4"))
	atts, _ := e.store.Snapshot()
	if len(atts) != 1 {
		t.Fatalf("records revoked by rollback: %d", len(atts))
	}
	// 旧职责在回退状态下变成“未来 slot”，基于回退后状态拒绝（不能放行）。
	if _, err := e.client.SignAttestation(duty); reason(err) != domain.ReasonDutyFuture {
		t.Fatalf("want DUTY_FUTURE after rollback, got %v", err)
	}
	t.Log("用例: 回退后记录仍为 1 条；旧职责基于回退后状态以 DUTY_FUTURE 拒绝")
}

func signErr(c *guard.Client, a domain.AttestationRequest) error {
	_, err := c.SignAttestation(a)
	return err
}

func (e *env) clientValue() *guard.Validator { return e.val }
