package interchange_test

import (
	"encoding/hex"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"github.com/lechandonga/validator-slashing-guard-go/internal/chain"
	"github.com/lechandonga/validator-slashing-guard-go/internal/interchange"
	"github.com/lechandonga/validator-slashing-guard-go/internal/signer"
	"github.com/lechandonga/validator-slashing-guard-go/internal/store"
	"github.com/lechandonga/validator-slashing-guard-go/internal/types"
)

func validatorID() types.ValidatorID {
	var v types.ValidatorID
	v[0] = 0xC3
	v[47] = 0x09
	return v
}

type env struct {
	v  types.ValidatorID
	ch *chain.State
	st *store.Store
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "guard")
	v := validatorID()
	ch, err := chain.LoadOrCreate(filepath.Join(dir, "chain-state.json"), v)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dir, v, ch.GenesisValidatorsRoot)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return &env{v: v, ch: ch, st: st}
}

func rootHex(b byte) string {
	var r types.Root
	r[0] = b
	return "0x" + hex.EncodeToString(r[:])
}

func validFile(v types.ValidatorID, gvr types.Root) string {
	return `{
  "metadata": {
    "interchange_format_version": "5",
    "genesis_validators_root": "0x` + hex.EncodeToString(gvr[:]) + `"
  },
  "data": [
    {
      "pubkey": "0x` + hex.EncodeToString(v[:]) + `",
      "signed_blocks": [
        {"slot": "42", "signing_root": "` + rootHex(0xAA) + `"}
      ],
      "signed_attestations": [
        {"source_epoch": "1", "target_epoch": "3", "signing_root": "` + rootHex(0xBB) + `"}
      ]
    }
  ]
}`
}

func reason(t *testing.T, err error) types.Reason {
	t.Helper()
	var ve *types.ValidationError
	if errors.As(err, &ve) {
		return ve.Reason
	}
	t.Fatalf("want ValidationError, got %v", err)
	return ""
}

// TestBusinessImportExport 业务：标准导入、幂等再导入与导出往返。
func TestBusinessImportExport(t *testing.T) {
	t.Run("import_then_roundtrip_export", func(t *testing.T) {
		e := newEnv(t)
		res, err := interchange.Import([]byte(validFile(e.v, e.ch.GenesisValidatorsRoot)), e.v, e.ch.GenesisValidatorsRoot, e.st)
		if err != nil {
			t.Fatalf("import: %v", err)
		}
		if res.NewAttestations != 1 || res.NewProposals != 1 {
			t.Fatalf("unexpected import counts: %+v", res)
		}
		out, err := interchange.Export(e.st, e.v, e.ch.GenesisValidatorsRoot)
		if err != nil {
			t.Fatal(err)
		}
		res2, err := interchange.Import(out, e.v, e.ch.GenesisValidatorsRoot, e.st)
		if err != nil {
			t.Fatalf("reimport: %v", err)
		}
		if res2.NewAttestations != 0 || res2.NewProposals != 0 {
			t.Fatalf("idempotent reimport must add nothing: %+v", res2)
		}
	})

	t.Run("reject_unknown_fields_and_truncated_json", func(t *testing.T) {
		e := newEnv(t)
		bad := []byte(`{"metadata":{},"data":[],"surprise":1}`)
		if got := reason(t, mustErr(interchange.Import(bad, e.v, e.ch.GenesisValidatorsRoot, e.st))); got != types.ReasonInterchangeInvalid {
			t.Fatalf("want interchange_invalid, got %s", got)
		}
		bad = []byte(`{"metadata": {"interchange_format_version": "5"`)
		if got := reason(t, mustErr(interchange.Import(bad, e.v, e.ch.GenesisValidatorsRoot, e.st))); got != types.ReasonInterchangeInvalid {
			t.Fatalf("want interchange_invalid for truncated json, got %s", got)
		}
	})

	t.Run("reject_wrong_gvr_and_foreign_validator", func(t *testing.T) {
		e := newEnv(t)
		var otherGVR types.Root
		otherGVR[31] = 1
		if got := reason(t, mustErr(interchange.Import([]byte(validFile(e.v, otherGVR)), e.v, e.ch.GenesisValidatorsRoot, e.st))); got != types.ReasonInterchangeInvalid {
			t.Fatalf("want interchange_invalid for gvr mismatch, got %s", got)
		}
		var otherV types.ValidatorID
		otherV[0] = 0xFF
		if got := reason(t, mustErr(interchange.Import([]byte(validFile(otherV, e.ch.GenesisValidatorsRoot)), e.v, e.ch.GenesisValidatorsRoot, e.st))); got != types.ReasonInterchangeInvalid {
			t.Fatalf("want interchange_invalid for foreign validator, got %s", got)
		}
	})

	t.Run("reject_bad_epoch_geometry", func(t *testing.T) {
		e := newEnv(t)
		bad := `{"metadata":{"interchange_format_version":"5","genesis_validators_root":"0x` +
			hex.EncodeToString(e.ch.GenesisValidatorsRoot[:]) +
			`"},"data":[{"pubkey":"0x` + hex.EncodeToString(e.v[:]) +
			`","signed_blocks":[],"signed_attestations":[{"source_epoch":"5","target_epoch":"2","signing_root":"` + rootHex(0x01) + `"}]}]}`
		if got := reason(t, mustErr(interchange.Import([]byte(bad), e.v, e.ch.GenesisValidatorsRoot, e.st))); got != types.ReasonInterchangeInvalid {
			t.Fatalf("want interchange_invalid for source>target, got %s", got)
		}
		if len(e.st.Attestations()) != 0 {
			t.Fatalf("rejected import must not write anything")
		}
	})
}

// TestBusinessImportConflicts 业务：冲突整体拒绝，不污染既有记录。
func TestBusinessImportConflicts(t *testing.T) {
	t.Run("double_attestation_conflict_is_atomic", func(t *testing.T) {
		e := newEnv(t)
		if _, err := interchange.Import([]byte(validFile(e.v, e.ch.GenesisValidatorsRoot)), e.v, e.ch.GenesisValidatorsRoot, e.st); err != nil {
			t.Fatal(err)
		}
		before := len(e.st.Attestations())
		// 同 target=3 但不同 signing_root 的导入条目必须冲突。
		conflict := `{"metadata":{"interchange_format_version":"5","genesis_validators_root":"0x` +
			hex.EncodeToString(e.ch.GenesisValidatorsRoot[:]) +
			`"},"data":[{"pubkey":"0x` + hex.EncodeToString(e.v[:]) +
			`","signed_blocks":[],"signed_attestations":[` +
			`{"source_epoch":"1","target_epoch":"5","signing_root":"` + rootHex(0xCC) + `"},` +
			`{"source_epoch":"2","target_epoch":"3","signing_root":"` + rootHex(0xDD) + `"}` +
			`]}]}`
		err := mustErr(interchange.Import([]byte(conflict), e.v, e.ch.GenesisValidatorsRoot, e.st))
		if got := reason(t, err); got != types.ReasonDoubleAttestation {
			t.Fatalf("want double_attestation, got %s", got)
		}
		if len(e.st.Attestations()) != before {
			t.Fatalf("conflicting import partially wrote records: before=%d after=%d", before, len(e.st.Attestations()))
		}
	})

	t.Run("surrounding_conflict_rejected", func(t *testing.T) {
		e := newEnv(t)
		load := `{"metadata":{"interchange_format_version":"5","genesis_validators_root":"0x` +
			hex.EncodeToString(e.ch.GenesisValidatorsRoot[:]) +
			`"},"data":[{"pubkey":"0x` + hex.EncodeToString(e.v[:]) +
			`","signed_blocks":[],"signed_attestations":[{"source_epoch":"2","target_epoch":"4","signing_root":"` + rootHex(0x01) + `"}]}]}`
		if _, err := interchange.Import([]byte(load), e.v, e.ch.GenesisValidatorsRoot, e.st); err != nil {
			t.Fatal(err)
		}
		bad := `{"metadata":{"interchange_format_version":"5","genesis_validators_root":"0x` +
			hex.EncodeToString(e.ch.GenesisValidatorsRoot[:]) +
			`"},"data":[{"pubkey":"0x` + hex.EncodeToString(e.v[:]) +
			`","signed_blocks":[],"signed_attestations":[{"source_epoch":"1","target_epoch":"5","signing_root":"` + rootHex(0x02) + `"}]}]}`
		if got := reason(t, mustErr(interchange.Import([]byte(bad), e.v, e.ch.GenesisValidatorsRoot, e.st))); got != types.ReasonSurrounding {
			t.Fatalf("want surrounding_attestation, got %s", got)
		}
	})

	t.Run("double_block_conflict_rejected", func(t *testing.T) {
		e := newEnv(t)
		if _, err := interchange.Import([]byte(validFile(e.v, e.ch.GenesisValidatorsRoot)), e.v, e.ch.GenesisValidatorsRoot, e.st); err != nil {
			t.Fatal(err)
		}
		bad := `{"metadata":{"interchange_format_version":"5","genesis_validators_root":"0x` +
			hex.EncodeToString(e.ch.GenesisValidatorsRoot[:]) +
			`"},"data":[{"pubkey":"0x` + hex.EncodeToString(e.v[:]) +
			`","signed_blocks":[{"slot":"42","signing_root":"` + rootHex(0x77) + `"}],"signed_attestations":[]}]}`
		if got := reason(t, mustErr(interchange.Import([]byte(bad), e.v, e.ch.GenesisValidatorsRoot, e.st))); got != types.ReasonDoubleProposal {
			t.Fatalf("want double_proposal, got %s", got)
		}
	})
}

// TestBusinessImportSignConcurrency 业务：导入与实时签署并发时，
// store 级互斥把操作线性化；无论交织顺序如何，最终不变量成立且结论可复现。
func TestBusinessImportSignConcurrency(t *testing.T) {
	for iter := 0; iter < 50; iter++ {
		e := newEnv(t)
		sg := signer.New(e.v, e.ch, e.st)
		for e.ch.CurrentSlot < 25 {
			if _, _, err := e.ch.Advance(); err != nil {
				t.Fatal(err)
			}
		}

		// 导入文件包含 target epoch 3 的记录；实时签署也尝试签 epoch 3。
		file := `{"metadata":{"interchange_format_version":"5","genesis_validators_root":"0x` +
			hex.EncodeToString(e.ch.GenesisValidatorsRoot[:]) +
			`"},"data":[{"pubkey":"0x` + hex.EncodeToString(e.v[:]) +
			`","signed_blocks":[],"signed_attestations":[{"source_epoch":"1","target_epoch":"3","signing_root":"` + rootHex(0x42) + `"}]}]}`

		block, _ := e.ch.BlockRoot(25)
		duty := types.AttestationDuty{
			Validator: e.v, Slot: 25, BeaconBlockRoot: block,
			SourceEpoch: e.ch.FinalizedEpoch, TargetEpoch: 3,
			SigningRoot: signingRoot("live", block),
		}

		var wg sync.WaitGroup
		var importErr, signErr error
		start := make(chan struct{})
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			importErr = sg.UnderLock(func() error {
				_, ierr := interchange.Import([]byte(file), e.v, e.ch.GenesisValidatorsRoot, e.st)
				return ierr
			})
		}()
		go func() { defer wg.Done(); <-start; _, signErr = sg.SignAttestation(duty) }()
		close(start)
		wg.Wait()

		// 任一顺序下：恰有一方成功、另一方被 double_attestation 拒绝；
		// 绝不会两条冲突记录同时存在。
		target3 := 0
		for _, a := range e.st.Attestations() {
			if a.TargetEpoch == 3 {
				target3++
			}
		}
		if target3 != 1 {
			t.Fatalf("iter %d: invariant violated, target-epoch-3 records = %d (importErr=%v signErr=%v)",
				iter, target3, importErr, signErr)
		}
		if importErr != nil && signErr != nil {
			t.Fatalf("iter %d: both operations failed unexpectedly", iter)
		}
	}
}

func signingRoot(tag string, block types.Root) types.Root {
	var r types.Root
	copy(r[:4], []byte(tag))
	for i := 0; i < 28; i++ {
		r[i+4] = block[i]
	}
	return r
}

func mustErr(_ interchange.ImportResult, err error) error {
	if err == nil {
		panic("expected error")
	}
	return err
}
