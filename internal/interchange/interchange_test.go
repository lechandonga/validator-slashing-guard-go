package interchange_test

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"github.com/lechandonga/validator-slashing-guard-go/internal/domain"
	"github.com/lechandonga/validator-slashing-guard-go/internal/interchange"
	"github.com/lechandonga/validator-slashing-guard-go/internal/store"
)

var gvr = []byte("local-genesis-validators-root-0001")

func openStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "records.json"))
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func wrapFile(gvrHex, body string) []byte {
	return []byte(`{"metadata":{"interchange_format_version":"5","genesis_validators_root":"` +
		gvrHex + `"},"data":[` + body + `]}`)
}

func vEntry(pk, atts, blocks string) string {
	return fmt.Sprintf(`{"pubkey":%q,"signed_attestations":[%s],"signed_blocks":[%s]}`, pk, atts, blocks)
}

func att(source, target uint64, root string) string {
	return fmt.Sprintf(`{"source_epoch":%d,"target_epoch":%d,"beacon_block_root":%q}`, source, target, root)
}

func errReason(err error) string {
	var ge *domain.GuardError
	if errors.As(err, &ge) {
		return ge.Reason
	}
	return ""
}

func TestImportValidAndIdempotent(t *testing.T) {
	t.Log("业务: 互导导入 —— 合法文件合并，重复导入幂等")
	st := openStore(t)
	pk := "0xaaaa"
	mapping := map[string]uint64{pk: 7}
	gvrHex := "0x" + fmt.Sprintf("%x", gvr)
	f := wrapFile(gvrHex, vEntry(pk, att(0, 1, "0x1111")+","+att(1, 2, "0x2222"), `{"slot":5},{"slot":6}`))

	n, err := interchange.Import(st, f, gvr, mapping)
	if err != nil {
		t.Fatalf("first import: %v", err)
	}
	if n != 4 {
		t.Fatalf("imported=%d want 4", n)
	}
	n2, err := interchange.Import(st, f, gvr, mapping)
	if err != nil {
		t.Fatalf("re-import: %v", err)
	}
	if n2 != 0 {
		t.Fatalf("re-import added=%d want 0", n2)
	}
	atts, blocks := st.Snapshot()
	if len(atts) != 2 || len(blocks) != 2 {
		t.Fatalf("atts=%d blocks=%d", len(atts), len(blocks))
	}
	t.Log("用例: 4 条记录导入成功，再次导入新增 0 条")
}

func TestImportMalformedRejected(t *testing.T) {
	t.Log("业务: 互导导入 —— 截断/版本不符/根不符等整体拒绝且不污染既有记录")
	st := openStore(t)
	pk := "0xaaaa"
	mapping := map[string]uint64{pk: 7}
	gvrHex := "0x" + fmt.Sprintf("%x", gvr)

	good := wrapFile(gvrHex, vEntry(pk, att(0, 1, "0x1111"), ""))
	if _, err := interchange.Import(st, good, gvr, mapping); err != nil {
		t.Fatal(err)
	}
	version4 := []byte(`{"metadata":{"interchange_format_version":"4","genesis_validators_root":"` +
		gvrHex + `"},"data":[{"pubkey":"0xaaaa","signed_attestations":[],"signed_blocks":[]}]}`)

	cases := []struct {
		name string
		raw  []byte
	}{
		{"JSON 被截断", []byte(`{"metadata":{"interchange_format_version":"5"`)},
		{"格式版本不支持", version4},
		{"genesis 根不匹配", wrapFile("0xdeadbeef", vEntry(pk, att(0, 1, "0x1111"), ""))},
		{"source>target", wrapFile(gvrHex, vEntry(pk, att(3, 1, "0x1111"), ""))},
		{"未知验证者公钥", wrapFile(gvrHex, vEntry("0xbbbb", att(0, 1, "0x1111"), ""))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n, err := interchange.Import(st, tc.raw, gvr, mapping)
			if errReason(err) != domain.ReasonImportInvalid {
				t.Fatalf("want IMPORT_INVALID, got %v", err)
			}
			if n != 0 {
				t.Fatalf("partial import detected: %d", n)
			}
			atts, blocks := st.Snapshot()
			if len(atts) != 1 || len(blocks) != 0 {
				t.Fatalf("records polluted: atts=%d blocks=%d", len(atts), len(blocks))
			}
			t.Logf("用例[%s] 整体拒绝，既有 1 条记录未被污染", tc.name)
		})
	}
}

func TestImportConflictAtomic(t *testing.T) {
	t.Log("业务: 互导导入 —— 与既有记录冲突时整体拒绝、不部分写入")
	st := openStore(t)
	pk := "0xaaaa"
	mapping := map[string]uint64{pk: 7}
	gvrHex := "0x" + fmt.Sprintf("%x", gvr)

	base := wrapFile(gvrHex, vEntry(pk, att(0, 2, "0x1111"), `{"slot":3}`))
	if _, err := interchange.Import(st, base, gvr, mapping); err != nil {
		t.Fatal(err)
	}

	// 文件内含 double vote：两条 target=2 但根不同 —— 第二条必须整体拒绝
	double := wrapFile(gvrHex, vEntry(pk, att(0, 2, "0x1111")+","+att(0, 2, "0x2222"), ""))
	if _, err := interchange.Import(st, double, gvr, mapping); errReason(err) != domain.ReasonImportConflict {
		t.Fatalf("want IMPORT_CONFLICT, got %v", err)
	}

	// surround：先导入大区间 (0,4)，再导入被包含的 (1,3)
	st2 := openStore(t)
	big := wrapFile(gvrHex, vEntry(pk, att(0, 4, "0x3333"), ""))
	if _, err := interchange.Import(st2, big, gvr, mapping); err != nil {
		t.Fatal(err)
	}
	surrounded := wrapFile(gvrHex, vEntry(pk, att(1, 3, "0x4444"), ""))
	if _, err := interchange.Import(st2, surrounded, gvr, mapping); errReason(err) != domain.ReasonImportConflict {
		t.Fatalf("want surround IMPORT_CONFLICT, got %v", err)
	}

	// 相同区块 slot 记录幂等，不新增
	if _, err := interchange.Import(st, wrapFile(gvrHex, vEntry(pk, "", `{"slot":3}`)), gvr, mapping); err != nil {
		t.Fatalf("identical block must be idempotent: %v", err)
	}
	atts, blocks := st.Snapshot()
	if len(atts) != 1 || len(blocks) != 1 {
		t.Fatalf("conflict polluted records: atts=%d blocks=%d", len(atts), len(blocks))
	}
	t.Log("用例: double vote / surround 导入整体拒绝；记录集合保持冲突前状态")
}

func TestConcurrentMergeDeterministic(t *testing.T) {
	t.Log("业务: 导入并发 —— 结论确定可复现，记录恒为并集且无部分写入")
	pk := "0xaaaa"
	mapping := map[string]uint64{pk: 1}
	gvrHex := "0x" + fmt.Sprintf("%x", gvr)
	for iter := 0; iter < 25; iter++ {
		st := openStore(t)
		files := [][]byte{
			wrapFile(gvrHex, vEntry(pk, att(10, 11, "0xaaaa"), "")),
			wrapFile(gvrHex, vEntry(pk, att(12, 13, "0xbbbb"), `{"slot":20}`)),
			wrapFile(gvrHex, vEntry(pk, att(10, 11, "0xaaaa"), "")), // 幂等重复
		}
		var wg sync.WaitGroup
		errs := make([]error, len(files))
		start := make(chan struct{})
		for i, f := range files {
			wg.Add(1)
			go func(i int, f []byte) {
				defer wg.Done()
				<-start
				_, errs[i] = interchange.Import(st, f, gvr, mapping)
			}(i, f)
		}
		close(start)
		wg.Wait()
		for _, e := range errs {
			if e != nil {
				t.Fatalf("iter %d unexpected err: %v", iter, e)
			}
		}
		atts, blocks := st.Snapshot()
		if len(atts) != 2 || len(blocks) != 1 {
			t.Fatalf("iter %d: atts=%d blocks=%d want 2/1", iter, len(atts), len(blocks))
		}
	}
	t.Log("用例: 25 轮三路并发导入，最终恒为 2 证明 + 1 区块")
}

func TestExportRoundTrip(t *testing.T) {
	t.Log("业务: 导出/再导入往返 —— 记录集合一致")
	st := openStore(t)
	pk := "0xaaaa"
	mapping := map[string]uint64{pk: 1}
	gvrHex := "0x" + fmt.Sprintf("%x", gvr)
	f := wrapFile(gvrHex, vEntry(pk, att(0, 1, "0x1111")+","+att(1, 3, "0x2222"), `{"slot":2}`))
	if _, err := interchange.Import(st, f, gvr, mapping); err != nil {
		t.Fatal(err)
	}
	out, err := interchange.Export(st, gvr, map[uint64]string{1: pk})
	if err != nil {
		t.Fatal(err)
	}
	st2 := openStore(t)
	n, err := interchange.Import(st2, out, gvr, mapping)
	if err != nil {
		t.Fatalf("round-trip import: %v", err)
	}
	if n != 3 {
		t.Fatalf("fresh round-trip import added %d want 3", n)
	}
	// 在 st2 上再次导入同一份导出文件必须幂等
	if n2, err := interchange.Import(st2, out, gvr, mapping); err != nil || n2 != 0 {
		t.Fatalf("repeat round-trip: added=%d err=%v", n2, err)
	}
	a1, b1 := st.Snapshot()
	a2, b2 := st2.Snapshot()
	if len(a1) != len(a2) || len(b1) != len(b2) {
		t.Fatalf("snapshot mismatch %d/%d vs %d/%d", len(a1), len(b1), len(a2), len(b2))
	}
	t.Log("用例: 导出后导入空库，再导回幂等，集合一致")
}
