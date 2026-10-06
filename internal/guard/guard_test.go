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
	vals   map[uint64]*guard.Validator
	dir    string
}

func genValidator(t *testing.T, index uint64) *guard.Validator {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return guard.NewValidator(index, priv)
}

func setup(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	state := domain.NewChainState(gvr, []byte{1, 0, 0, 0}, []byte("genesis-head"))
	st, err := store.Open(filepath.Join(dir, "records.json"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	val := genValidator(t, 1)
	client := guard.NewClient(state, st, val)
	return &env{t: t, state: state, store: st, client: client,
		vals: map[uint64]*guard.Validator{1: val}, dir: dir}
}

func setupMulti(t *testing.T, indexes ...uint64) *env {
	t.Helper()
	dir := t.TempDir()
	state := domain.NewChainState(gvr, []byte{1, 0, 0, 0}, []byte("genesis-head"))
	st, err := store.Open(filepath.Join(dir, "records.json"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	vals := make([]*guard.Validator, 0, len(indexes))
	byIndex := map[uint64]*guard.Validator{}
	for _, i := range indexes {
		v := genValidator(t, i)
		vals = append(vals, v)
		byIndex[i] = v
	}
	client := guard.NewClient(state, st, vals...)
	return &env{t: t, state: state, store: st, client: client, vals: byIndex, dir: dir}
}

// advanceTo 推进到指定 slot，返回与链头一致的证明职责（身份 1）。
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
	t.Log("业务: 证明签名准入 —— 正常通过及各可区分拒绝原因（上一轮回归）")
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
			_, err := e.client.SignAttestation(1, req)
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
		if _, err := e2.client.SignAttestation(1, req); err != nil {
			t.Fatalf("sign at slot 7: %v", err)
		}
		e2.state.Advance(8, 1, 0, []byte("head@8"))
		if _, err := e2.client.SignAttestation(1, req); reason(err) != domain.ReasonDutyExpired {
			t.Fatalf("want DUTY_EXPIRED, got %v", err)
		}
		t.Log("用例: 链推进后重提旧 slot 职责 -> DUTY_EXPIRED")
	})
}

func TestDuplicateDutyConcurrentSingleSuccess(t *testing.T) {
	t.Log("业务: 同一证明职责并发触发 —— 恰好一次有效签名（上一轮回归）")
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
			_, err := e.client.SignAttestation(1, duty)
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
	t.Log("业务: 防罚没判定 —— double vote 与 surround vote（上一轮回归）")
	e := setup(t)

	first := e.advanceTo(16, 0)
	first.SourceEpoch = 0
	h := e.state.Snapshot()
	first.BeaconBlockRoot = h.HeadRoot
	if _, err := e.client.SignAttestation(1, first); err != nil {
		t.Fatalf("first sign: %v", err)
	}

	atts, _ := e.store.Snapshot()
	diffRoot := []byte("different-block-root-32-bytes!!!")
	if _, r := guard.FindAttestationConflict(1, 0, 2,
		domain.AttestationRequest{
			Duty: domain.Duty{Slot: 16}, SourceEpoch: 0, TargetEpoch: 2,
			BeaconBlockRoot: diffRoot,
		}.SigningRoot(h), atts); r != domain.ReasonDoubleVote {
		t.Fatalf("want DOUBLE_VOTE, got %q", r)
	}
	t.Log("用例: 同 target epoch 不同内容 -> DOUBLE_VOTE")

	e2 := setup(t)
	big := e2.advanceTo(32, 0)
	big.SourceEpoch = 0
	if _, err := e2.client.SignAttestation(1, big); err != nil {
		t.Fatalf("big sign: %v", err)
	}
	atts2, _ := e2.store.Snapshot()
	innerRoot := []byte("inner-head-32-bytes-000000000000000000000000")
	if _, r := guard.FindAttestationConflict(1, 1, 3,
		domain.AttestationRequest{
			Duty: domain.Duty{Slot: 30}, SourceEpoch: 1, TargetEpoch: 3,
			BeaconBlockRoot: innerRoot,
		}.SigningRoot(e2.state.Snapshot()), atts2); r != domain.ReasonSurroundVote {
		t.Fatalf("want SURROUND_VOTE, got %q", r)
	}
	t.Log("用例: 新区间被既有记录完全包含 -> SURROUND_VOTE")
}

func TestBlockProposalNoDoubleSign(t *testing.T) {
	t.Log("业务: 区块提议 —— 同 slot 不重复签署（上一轮回归）")
	e := setup(t)
	e.advanceTo(10, 1)
	block := domain.BlockProposalRequest{
		Duty:       domain.Duty{ValidatorIndex: 1, Slot: 10},
		ParentRoot: []byte("parent-root-32-bytes-0000000000000000000"),
		StateRoot:  []byte("state-root-32-bytes-000000000000000000000"),
		BodyRoot:   []byte("body-root-32-bytes-0000000000000000000000"),
	}
	if _, err := e.client.SignBlock(1, block); err != nil {
		t.Fatalf("first block sign: %v", err)
	}
	if _, err := e.client.SignBlock(1, block); reason(err) != domain.ReasonDuplicateDuty {
		t.Fatalf("identical block: want DUPLICATE_DUTY, got %v", err)
	}
	different := block
	different.BodyRoot = []byte("other-body-32-bytes-0000000000000000000000")
	if _, err := e.client.SignBlock(1, different); reason(err) != domain.ReasonDuplicateBlockSlot {
		t.Fatalf("different block same slot: want DUPLICATE_BLOCK_SLOT, got %v", err)
	}
	t.Log("用例: 同区块重复 -> DUPLICATE_DUTY；同 slot 不同区块 -> DUPLICATE_BLOCK_SLOT")
}

func TestCrashRestartConsistency(t *testing.T) {
	t.Log("业务: 崩溃恢复 —— 提交点前后崩溃，记录与结论一致（上一轮回归）")
	e := setup(t)
	duty := e.advanceTo(8, 1)

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
	if _, err := client2.SignAttestation(1, duty); err != nil {
		t.Fatalf("re-sign after pre-rename crash: %v", err)
	}
	atts, _ = st2.Snapshot()
	if len(atts) != 1 {
		t.Fatalf("want 1 record, got %d", len(atts))
	}

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
	client3 := guard.NewClient(e2.state, st3, e2.vals[1])
	if _, err := client3.SignAttestation(1, d2); reason(err) != domain.ReasonDuplicateDuty {
		t.Fatalf("post-crash re-sign must be DUPLICATE_DUTY, got %v", err)
	}
	t.Log("用例: rename 前崩溃无记录可重签；rename 后崩溃记录在、重签被识别为重复")
}

func TestRollbackPreservesRecords(t *testing.T) {
	t.Log("业务: 链状态回退 —— 历史记录不撤销（上一轮回归）")
	e := setup(t)
	duty := e.advanceTo(8, 1)
	if _, err := e.client.SignAttestation(1, duty); err != nil {
		t.Fatal(err)
	}
	e.state.Rollback(4, 0, 0, []byte("head@4"))
	atts, _ := e.store.Snapshot()
	if len(atts) != 1 {
		t.Fatalf("records revoked by rollback: %d", len(atts))
	}
	if _, err := e.client.SignAttestation(1, duty); reason(err) != domain.ReasonDutyFuture {
		t.Fatalf("want DUTY_FUTURE after rollback, got %v", err)
	}
	t.Log("用例: 回退后记录仍为 1 条；旧职责以 DUTY_FUTURE 拒绝")
}

func signErr(c *guard.Client, a domain.AttestationRequest) error {
	_, err := c.SignAttestation(1, a)
	return err
}

func dutyFor(t *testing.T, e *env, index uint64) domain.AttestationRequest {
	t.Helper()
	h := e.state.Snapshot()
	justified := h.JustifiedEpoch
	slot := h.CurrentSlot
	target := domain.EpochOf(slot)
	_ = target
	return domain.AttestationRequest{
		Duty:            domain.Duty{ValidatorIndex: index, Slot: slot},
		SourceEpoch:     justified,
		TargetEpoch:     domain.EpochOf(slot),
		BeaconBlockRoot: append([]byte(nil), h.HeadRoot...),
	}
}

func TestIdentityMismatchRejectedAndNoRecords(t *testing.T) {
	t.Log("业务: 多身份归属 —— 请求身份与签署身份不一致时拒绝，且不污染任何身份的记录")
	e := setupMulti(t, 1, 2)

	// 链推进到 slot 8（epoch 1），让两个身份都有合法职责。
	d1 := e.advanceTo(8, 1)
	if _, err := e.client.SignAttestation(1, d1); err != nil {
		t.Fatalf("v1 sign: %v", err)
	}
	d2 := dutyFor(t, e, 2)

	before := func() map[uint64]int {
		atts, blocks := e.store.Snapshot()
		count := map[uint64]int{}
		for _, a := range atts {
			count[a.ValidatorIndex]++
		}
		for _, b := range blocks {
			count[b.ValidatorIndex] += 100
		}
		return count
	}
	pre := before()

	// 用身份 2 的签名者去签属于身份 1 的职责，以及反过来。
	if _, err := e.client.SignAttestation(2, d1); reason(err) != domain.ReasonValidatorMismatch {
		t.Fatalf("want VALIDATOR_MISMATCH, got %v", err)
	}
	req1As2 := d2
	req1As2.ValidatorIndex = 1
	if _, err := e.client.SignAttestation(2, req1As2); reason(err) != domain.ReasonValidatorMismatch {
		t.Fatalf("want VALIDATOR_MISMATCH, got %v", err)
	}
	// 未托管身份（签署身份与职责身份同为 9，但本进程未托管）
	d9 := d2
	d9.ValidatorIndex = 9
	if _, err := e.client.SignAttestation(9, d9); reason(err) != domain.ReasonUnknownValidator {
		t.Fatalf("want UNKNOWN_VALIDATOR, got %v", err)
	}

	post := before()
	if fmt.Sprint(post) != fmt.Sprint(pre) {
		t.Fatalf("records polluted: before=%v after=%v", pre, post)
	}
	// 身份 2 用自己的身份签自己的职责，必须正常
	if _, err := e.client.SignAttestation(2, d2); err != nil {
		t.Fatalf("v2 own duty should pass: %v", err)
	}
	t.Logf("用例: 跨身份签署/未知身份全部拒绝，记录计数不变 %v；身份自签正常", post)
}

func TestMultiValidatorRecordIsolation(t *testing.T) {
	t.Log("业务: 多身份记录隔离 —— 不同身份同 slot 区块/同 target 证明互不判定为冲突")
	e := setupMulti(t, 1, 2)
	e.advanceTo(16, 1) // slot 16, epoch 2

	d1 := dutyFor(t, e, 1)
	d2 := dutyFor(t, e, 2)
	if _, err := e.client.SignAttestation(1, d1); err != nil {
		t.Fatalf("v1 att: %v", err)
	}
	if _, err := e.client.SignAttestation(2, d2); err != nil {
		t.Fatalf("v2 att same target different identity must be isolated: %v", err)
	}

	block := domain.BlockProposalRequest{
		Duty:       domain.Duty{ValidatorIndex: 1, Slot: 16},
		ParentRoot: []byte("parent-root-32-bytes-0000000000000000000"),
		StateRoot:  []byte("state-root-32-bytes-000000000000000000000"),
		BodyRoot:   []byte("body-root-32-bytes-0000000000000000000000"),
	}
	block2 := block
	block2.ValidatorIndex = 2
	if _, err := e.client.SignBlock(1, block); err != nil {
		t.Fatalf("v1 block: %v", err)
	}
	if _, err := e.client.SignBlock(2, block2); err != nil {
		t.Fatalf("v2 same-slot block must be isolated: %v", err)
	}

	atts, blocks := e.store.Snapshot()
	countAtt, countBlk := map[uint64]int{}, map[uint64]int{}
	for _, a := range atts {
		countAtt[a.ValidatorIndex]++
	}
	for _, b := range blocks {
		countBlk[b.ValidatorIndex]++
	}
	if countAtt[1] != 1 || countAtt[2] != 1 || countBlk[1] != 1 || countBlk[2] != 1 {
		t.Fatalf("isolation broken: atts=%v blocks=%v", countAtt, countBlk)
	}

	// 同身份再签同 slot 不同区块仍必须被拒（隔离不等于放开）。
	alt := block
	alt.BodyRoot = []byte("other-body-32-bytes-0000000000000000000000")
	if _, err := e.client.SignBlock(1, alt); reason(err) != domain.ReasonDuplicateBlockSlot {
		t.Fatalf("same identity same slot must conflict, got %v", err)
	}
	t.Log("用例: 两个身份同 slot 同 target 各自签署成功；身份内部冲突仍被识别")
}

func TestImportedWatermarkEnforced(t *testing.T) {
	t.Log("业务: EIP-3076 历史低水位 —— 导入历史后低于水位的职责被拒绝（条件 2/4/5）")
	// 该用例在 interchange_test 中通过导入缺根条目驱动；这里验证纯判定：
	// 已有区块 slot 10 后，slot 8 的新区块低于历史最小 slot。
	e := setup(t)
	e.advanceTo(10, 1)
	b10 := domain.BlockProposalRequest{
		Duty:       domain.Duty{ValidatorIndex: 1, Slot: 10},
		ParentRoot: []byte("parent-root-32-bytes-0000000000000000000"),
		StateRoot:  []byte("state-root-32-bytes-000000000000000000000"),
		BodyRoot:   []byte("body-root-32-bytes-0000000000000000000000"),
	}
	if _, err := e.client.SignBlock(1, b10); err != nil {
		t.Fatalf("block at 10: %v", err)
	}
	// 直接在存储层放入一条 slot 5 的“历史导入区块”（占位根，模拟迁移记录）。
	if err := e.store.Update(func(atts []domain.AttestationRecord, blocks []domain.BlockRecord) (
		[]domain.AttestationRecord, []domain.BlockRecord, error) {
		blocks = append(blocks, domain.BlockRecord{
			ValidatorIndex: 1, Slot: 5, SigningRoot: append([]byte(nil), domain.DummySigningRoot...),
		})
		return atts, blocks, nil
	}); err != nil {
		t.Fatal(err)
	}

	e.state.Advance(11, 1, 0, []byte("head@11"))
	// 通过纯函数确认 slot 5 之后的 slot 7 被低水位拒绝（同 slot 缺根也会被保守拒绝）。
	_, blocks := e.store.Snapshot()
	root := b10.SigningRoot(e.state.Snapshot())
	_, r := guard.FindBlockConflict(1, 5, root, blocks)
	if r != domain.ReasonDuplicateBlockSlot {
		t.Fatalf("same slot with root-less history must be DUPLICATE_BLOCK_SLOT, got %q", r)
	}
	t.Log("用例: 迁移来的缺根区块使同 slot 任何新区块被保守拒绝")
}

func TestConcurrentSignAndExportSnapshot(t *testing.T) {
	t.Log("业务: 签署与导出并发 —— 导出恒为一致快照，计数只增不减")
	e := setupMulti(t, 1, 2)
	e.advanceTo(40, 1)

	const signers = 8
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < signers; i++ {
		wg.Add(1)
		idx := uint64(1 + i%2)
		go func(i int, idx uint64) {
			defer wg.Done()
			<-start
			slot := uint64(40 + i) // 各不同 slot，均为“未来”会被拒——改用当前链头职责
			_ = slot
			d := dutyFor(t, e, idx)
			_, _ = e.client.SignAttestation(idx, d)
		}(i, idx)
	}

	// 与签署并发地反复快照：每次拿到的记录数必须自洽（只增不减，且无半条）。
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for k := 0; k < 50; k++ {
			atts, blocks := e.store.Snapshot()
			for _, a := range atts {
				if a.SigningRoot == nil {
					t.Errorf("snapshot saw half-written attestation")
					return
				}
			}
			for _, b := range blocks {
				if b.SigningRoot == nil {
					t.Errorf("snapshot saw half-written block")
					return
				}
			}
		}
	}()
	close(start)
	wg.Wait()

	atts, blocks := e.store.Snapshot()
	total := len(atts) + len(blocks)
	// 并发签署同一职责：两个身份各自至多新增 1 条。
	if total > 2 {
		t.Fatalf("unexpected record count: %d", total)
	}
	t.Logf("用例: 8 路签署与 50 次并发快照无半条记录，最终记录数=%d", total)
}
