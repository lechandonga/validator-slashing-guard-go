package store_test

import (
	"path/filepath"
	"testing"

	"github.com/lechandonga/validator-slashing-guard-go/internal/domain"
	"github.com/lechandonga/validator-slashing-guard-go/internal/store"
)

func TestOpenRejectsCorruptFile(t *testing.T) {
	t.Log("业务: 存储加载 —— 被截断/损坏文件显式报错，绝不静默清空历史")
	dir := t.TempDir()
	path := filepath.Join(dir, "records.json")
	if err := osWriteFile(path, []byte(`{"version":1,"attestations":[{"`)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Open(path); err == nil {
		t.Fatal("corrupt file must fail loudly")
	}
	t.Log("用例: 损坏文件打开失败，避免把历史误判为空")
}

func TestAppendAcrossReopen(t *testing.T) {
	t.Log("业务: 存储追加 —— 多次开关存储，记录持续累积")
	dir := t.TempDir()
	path := filepath.Join(dir, "records.json")
	for i := 0; i < 5; i++ {
		st, err := store.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := st.AddBlock(domain.BlockRecord{ValidatorIndex: 1, Slot: uint64(i + 1)}); err != nil {
			t.Fatal(err)
		}
	}
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	_, blocks := st.Snapshot()
	if len(blocks) != 5 {
		t.Fatalf("blocks=%d want 5", len(blocks))
	}
	t.Log("用例: 5 次重开追加，最终 5 条区块记录")
}
