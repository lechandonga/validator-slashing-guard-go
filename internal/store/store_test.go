package store_test

import (
	"path/filepath"
	"sync"
	"testing"

	"github.com/lechandonga/validator-slashing-guard-go/internal/store"
	"github.com/lechandonga/validator-slashing-guard-go/internal/types"
)

func ids() (types.ValidatorID, types.Root) {
	var v types.ValidatorID
	v[0] = 7
	var g types.Root
	g[0] = 9
	return v, g
}

// TestBusinessStoreAppendOnly 业务：记录只追加不覆盖；并发追加后
// 重启重开数量与内容完全一致。
func TestBusinessStoreAppendOnly(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "guard")
	v, g := ids()
	st, err := store.Open(dir, v, g)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		i := i
		go func() {
			defer wg.Done()
			var sr types.Root
			sr[31] = byte(i)
			if err := st.AppendProposal(types.SignedProposal{Slot: uint64(i), SigningRoot: sr, BlockRoot: sr}); err != nil {
				t.Errorf("append: %v", err)
			}
		}()
	}
	wg.Wait()
	if len(st.Proposals()) != 100 {
		t.Fatalf("want 100 records, got %d", len(st.Proposals()))
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	// 重启后记录必须完整可恢复。
	st2, err := store.Open(dir, v, g)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	if len(st2.Proposals()) != 100 {
		t.Fatalf("after restart want 100 records, got %d", len(st2.Proposals()))
	}
}

// TestBusinessStoreIdentityMismatch 业务：数据库身份/GVR 不匹配必须拒绝打开。
func TestBusinessStoreIdentityMismatch(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "guard")
	v, g := ids()
	st, err := store.Open(dir, v, g)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()

	v2 := v
	v2[1] = 1
	if _, err := store.Open(dir, v2, g); err == nil {
		t.Fatal("expected identity mismatch rejection")
	}
	g2 := g
	g2[1] = 1
	if _, err := store.Open(dir, v, g2); err == nil {
		t.Fatal("expected GVR mismatch rejection")
	}
}
