package signer_test

import (
	"path/filepath"
	"testing"

	"github.com/lechandonga/validator-slashing-guard-go/internal/chain"
	"github.com/lechandonga/validator-slashing-guard-go/internal/signer"
	"github.com/lechandonga/validator-slashing-guard-go/internal/store"
	"github.com/lechandonga/validator-slashing-guard-go/internal/types"
)

func testValidator() types.ValidatorID {
	var v types.ValidatorID
	v[0] = 0xA1
	v[47] = 0xB2
	return v
}

func rootFromTag(tag string, slot uint64, block types.Root) types.Root {
	var r types.Root
	copy(r[:8], []byte(tag))
	for i := 0; i < 8; i++ {
		r[i+8] = byte(slot >> (i * 8))
	}
	for i := 0; i < 24; i++ {
		r[i+8] ^= block[i]
	}
	return r
}

type fixture struct {
	dir       string
	validator types.ValidatorID
	chain     *chain.State
	store     *store.Store
	signer    *signer.Signer
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "guard")
	v := testValidator()
	ch, err := chain.LoadOrCreate(filepath.Join(dir, "chain-state.json"), v)
	if err != nil {
		t.Fatalf("load chain: %v", err)
	}
	st, err := store.Open(dir, v, ch.GenesisValidatorsRoot)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return &fixture{
		dir: dir, validator: v, chain: ch, store: st,
		signer: signer.New(v, ch, st),
	}
}

// advanceTo 推进链到指定 slot。
func (f *fixture) advanceTo(t *testing.T, slot uint64) {
	t.Helper()
	for f.chain.CurrentSlot < slot {
		if _, _, err := f.chain.Advance(); err != nil {
			t.Fatalf("advance: %v", err)
		}
	}
}

// attestDuty 构造与当前链状态一致的证明职责。
func (f *fixture) attestDuty(slot uint64, tag string) types.AttestationDuty {
	block, ok := f.chain.BlockRoot(slot)
	if !ok {
		panic("no block at slot")
	}
	return types.AttestationDuty{
		Validator:       f.validator,
		Slot:            slot,
		BeaconBlockRoot: block,
		TargetEpoch:     types.EpochOf(slot),
		SourceEpoch:     f.chain.FinalizedEpoch,
		SigningRoot:     rootFromTag(tag, slot, block),
	}
}

func (f *fixture) proposalDuty(slot uint64) types.ProposalDuty {
	block, _ := f.chain.BlockRoot(slot)
	return types.ProposalDuty{
		Validator:   f.validator,
		Slot:        slot,
		BlockRoot:   block,
		SigningRoot: rootFromTag("proposal", slot, block),
	}
}
