package signer_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lechandonga/validator-slashing-guard-go/internal/chain"
	"github.com/lechandonga/validator-slashing-guard-go/internal/signer"
	"github.com/lechandonga/validator-slashing-guard-go/internal/store"
	"github.com/lechandonga/validator-slashing-guard-go/internal/types"
)

const crashExitCode = 42

// TestMain 以 CRASH_HELPER=1 运行时充当“会在固化后立即崩溃”的客户端进程。
func TestMain(m *testing.M) {
	if os.Getenv("CRASH_HELPER") == "1" {
		runCrashHelper()
		return
	}
	os.Exit(m.Run())
}

func runCrashHelper() {
	dir := os.Getenv("GUARD_DIR")
	kind := types.DutyKind(os.Getenv("CRASH_KIND"))

	v := testValidator()
	ch, err := chain.LoadOrCreate(filepath.Join(dir, "chain-state.json"), v)
	mustHelper(err)
	st, err := store.Open(dir, v, ch.GenesisValidatorsRoot)
	mustHelper(err)
	st.CrashHook = func(types.DutyKind, uint64) {
		// 记录已 fsync，但签名结果尚未返回：以非零退出模拟进程被杀死。
		os.Exit(crashExitCode)
	}
	sg := signer.New(v, ch, st)

	for ch.CurrentSlot < 20 {
		_, _, err = ch.Advance()
		mustHelper(err)
	}
	if kind == types.DutyProposal {
		// 关闭证明崩溃路径：直接构造 proposal fixture。
		f := &fixture{dir: dir, validator: v, chain: ch, store: st, signer: sg}
		_, err = sg.SignProposal(f.proposalDuty(20))
	} else {
		f := &fixture{dir: dir, validator: v, chain: ch, store: st, signer: sg}
		_, err = sg.SignAttestation(f.attestDuty(17, "att-crash"))
	}
	mustHelper(err)
	os.Exit(0)
}

func mustHelper(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// runCrashingSigner 在子进程中签署，固化后立即崩溃。
func runCrashingSigner(t *testing.T, dir, kind string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=TestMain")
	cmd.Env = append(os.Environ(),
		"CRASH_HELPER=1",
		"GUARD_DIR="+dir,
		"CRASH_KIND="+kind,
	)
	out, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == crashExitCode {
		return
	}
	t.Fatalf("expected crash exit %d, got err=%v output=%s", crashExitCode, err, out)
}

// TestBusinessCrashRecovery 业务：固化后崩溃——重启后记录存在，
// 重放同一职责得到 duplicate_duty（不会再签第二次），且数据库未损坏。
func TestBusinessCrashRecovery(t *testing.T) {
	cases := []struct {
		name string
		kind string
	}{
		{"attestation_crash_after_fsync", string(types.DutyAttestation)},
		{"proposal_crash_after_fsync", string(types.DutyProposal)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "guard")
			runCrashingSigner(t, dir, tc.kind)

			// 数据库文件必须是完整 JSON（原子写保证）。
			raw, err := os.ReadFile(filepath.Join(dir, "slashing-protection.json"))
			if err != nil {
				t.Fatalf("read db: %v", err)
			}
			var head map[string]json.RawMessage
			if err := json.Unmarshal(raw, &head); err != nil {
				t.Fatalf("db truncated/corrupt after crash: %v", err)
			}

			// 重启：链与记录都应可加载，锁可重新获取。
			v := testValidator()
			ch, err := chain.LoadOrCreate(filepath.Join(dir, "chain-state.json"), v)
			if err != nil {
				t.Fatalf("reload chain: %v", err)
			}
			st, err := store.Open(dir, v, ch.GenesisValidatorsRoot)
			if err != nil {
				t.Fatalf("reopen store: %v", err)
			}
			defer st.Close()

			if tc.kind == string(types.DutyProposal) {
				if len(st.Proposals()) != 1 || st.Proposals()[0].Signature == (types.Signature{}) {
					t.Fatalf("expected 1 durable proposal with embedded signature, got %+v", st.Proposals())
				}
				f := &fixture{dir: dir, validator: v, chain: ch, store: st, signer: signer.New(v, ch, st)}
				_, err = f.signer.SignProposal(f.proposalDuty(20))
				if got := reasonOf(t, err); got != types.ReasonDuplicateDuty {
					t.Fatalf("restart replay want duplicate_duty, got %s", got)
				}
			} else {
				if len(st.Attestations()) != 1 || st.Attestations()[0].Signature == (types.Signature{}) {
					t.Fatalf("expected 1 durable attestation with embedded signature, got %+v", st.Attestations())
				}
				f := &fixture{dir: dir, validator: v, chain: ch, store: st, signer: signer.New(v, ch, st)}
				_, err = f.signer.SignAttestation(f.attestDuty(17, "att-crash"))
				if got := reasonOf(t, err); got != types.ReasonDuplicateDuty {
					t.Fatalf("restart replay want duplicate_duty, got %s", got)
				}
			}
		})
	}
}

// TestBusinessCorruptDBFailsClosed 业务：损坏/截断的数据库必须 fail-closed，
// 拒绝启动而不是带着空记忆放行。
func TestBusinessCorruptDBFailsClosed(t *testing.T) {
	f := newFixture(t)
	f.advanceTo(t, 17)
	if _, err := f.signer.SignAttestation(f.attestDuty(17, "att-ok")); err != nil {
		t.Fatalf("sign: %v", err)
	}
	f.store.Close()

	dbPath := filepath.Join(f.dir, "slashing-protection.json")
	raw, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dbPath, raw[:len(raw)/2], 0o600); err != nil {
		t.Fatal(err)
	}

	v := testValidator()
	ch, err := chain.LoadOrCreate(filepath.Join(f.dir, "chain-state.json"), v)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Open(f.dir, v, ch.GenesisValidatorsRoot); err == nil ||
		!strings.Contains(err.Error(), "truncated or corrupt") {
		t.Fatalf("expected corrupt db to fail closed, got %v", err)
	}
}

// TestBusinessProcessLock 业务：两个客户端实例不能同时持有同一数据库。
func TestBusinessProcessLock(t *testing.T) {
	f := newFixture(t)
	v := f.validator
	if _, err := store.Open(f.dir, v, f.chain.GenesisValidatorsRoot); err == nil {
		t.Fatal("expected second store.Open to fail on held lock")
	}
}
