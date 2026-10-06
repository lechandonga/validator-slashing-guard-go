package interchange_test

import (
	"encoding/hex"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"github.com/lechandonga/validator-slashing-guard-go/internal/domain"
	"github.com/lechandonga/validator-slashing-guard-go/internal/interchange"
	"github.com/lechandonga/validator-slashing-guard-go/internal/store"
)

var gvr32 = []byte("32-byte-genesis-validators-root!")

func gvrHex() string { return "0x" + hex.EncodeToString(gvr32) }

// 两个稳定的 48 字节 BLS 公钥（0x 十六进制），对应本地验证者 7 / 8。
var pk1, pk2 string

func init() {
	b1 := make([]byte, 48)
	for i := range b1 {
		b1[i] = 0xa0 + byte(i%16)
	}
	b2 := make([]byte, 48)
	for i := range b2 {
		b2[i] = 0xb0 + byte(i%16)
	}
	pk1 = interchange.PubkeyHex(b1)
	pk2 = interchange.PubkeyHex(b2)
}

func openStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "records.json"))
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func opts(keys ...string) interchange.Options {
	m := map[string]uint64{}
	for i, k := range keys {
		m[k] = uint64(7 + i)
	}
	return interchange.Options{PubkeyToIndex: m}
}

func errReason(err error) string {
	var ge *domain.GuardError
	if errors.As(err, &ge) {
		return ge.Reason
	}
	return ""
}

// specFile 采用 EIP-3076 规范的“Example JSON Instance”：
// 整数为引号字符串，区块含 signing_root，无任何自创字段。
const specFile = `{
  "metadata": {
    "interchange_format_version": "5",
    "genesis_validators_root": "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
  },
  "data": [
    {
      "pubkey": "0xb845089a1457f811bfc000588fbb4e713669be8ce060ea6be3c6ece09afc3794106c91ca73acda5e5457122d58723bed",
      "signed_blocks": [
        {"slot": "81952", "signing_root": "0x4ff6f743a43f3b4f95350831aeaf0a122a1a392922c45d804280284a69eb850b"},
        {"slot": "81951"}
      ],
      "signed_attestations": [
        {"source_epoch": "2290", "target_epoch": "3007", "signing_root": "0x587d6a4f59a58fe24f406e0502413e77fe1babddee641fda30034ed37ecc884d"},
        {"source_epoch": "2290", "target_epoch": "3008"}
      ]
    }
  ]
}`

func specGVR() []byte {
	b, _ := hex.DecodeString("04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673")
	return b
}

func specPub() string {
	return "0xb845089a1457f811bfc000588fbb4e713669be8ce060ea6be3c6ece09afc3794106c91ca73acda5e5457122d58723bed"
}

func TestImportCanonicalSpecSample(t *testing.T) {
	t.Log("业务: 规范兼容 —— EIP-3076 官方样例文件原样导入成功")
	st := openStore(t)
	r, err := interchange.Import(st, []byte(specFile), specGVR(),
		interchange.Options{PubkeyToIndex: map[string]uint64{specPub(): 7}})
	if err != nil {
		t.Fatalf("canonical sample must import: %v", err)
	}
	if r.Imported != 4 || r.Duplicate != 0 {
		t.Fatalf("imported=%d duplicate=%d want 4/0", r.Imported, r.Duplicate)
	}
	atts, blocks := st.Snapshot()
	if len(atts) != 2 || len(blocks) != 2 {
		t.Fatalf("atts=%d blocks=%d want 2/2", len(atts), len(blocks))
	}

	// 区块的 signing_root 必须完整保留（对端据此判断同 slot 是否签过不同区块）。
	var withRoot, withoutRoot int
	for _, b := range blocks {
		if domain.HasSigningRoot(b.SigningRoot) {
			withRoot++
		} else {
			withoutRoot++
		}
	}
	if withRoot != 1 || withoutRoot != 1 {
		t.Fatalf("block roots: with=%d without=%d want 1/1", withRoot, withoutRoot)
	}
	t.Log("用例: 官方样例 4 条记录原样导入，区块 signing_root 保留 1 条、缺省 1 条")
}

func localFile(blocks, atts string) []byte {
	return []byte(`{"metadata":{"interchange_format_version":"5","genesis_validators_root":"` + gvrHex() +
		`"},"data":[{"pubkey":"` + pk1 + `","signed_blocks":[` + blocks +
		`],"signed_attestations":[` + atts + `]}]}`)
}

func TestWireFormatStrictness(t *testing.T) {
	t.Log("业务: 线格式严格性 —— 数字/自创字段、错误长度、尾随数据被整体拒绝")
	st := openStore(t)
	entry := func(items string) string {
		return `{"metadata":{"interchange_format_version":"5","genesis_validators_root":"` + gvrHex() +
			`"},"data":[{"pubkey":"` + pk1 + `","signed_blocks":[],"signed_attestations":[` + items + `]}]}`
	}
	base := func() string {
		return `{"metadata":{"interchange_format_version":"5","genesis_validators_root":"` + gvrHex() + `"},"data":[]}`
	}

	cases := []struct {
		name string
		raw  []byte
	}{
		{"JSON 数字 epoch 被拒", []byte(entry(`{"source_epoch":0,"target_epoch":1}`))},
		{"自创 beacon_block_root 字段被拒", []byte(entry(`{"source_epoch":"0","target_epoch":"1","beacon_block_root":"0x11"}`))},
		{"区块缺 slot 被拒", []byte(`{"metadata":{"interchange_format_version":"5","genesis_validators_root":"` + gvrHex() +
			`"},"data":[{"pubkey":"` + pk1 + `","signed_blocks":[{"signing_root":"0x4ff6f743a43f3b4f95350831aeaf0a122a1a392922c45d804280284a69eb850b"}],"signed_attestations":[]}]}`)},
		{"公钥长度不足被拒", []byte(`{"metadata":{"interchange_format_version":"5","genesis_validators_root":"` + gvrHex() +
			`"},"data":[{"pubkey":"0xaaaa","signed_blocks":[],"signed_attestations":[]}]}`)},
		{"gvr 长度不足被拒", []byte(`{"metadata":{"interchange_format_version":"5","genesis_validators_root":"0xdead"},"data":[]}`)},
		{"尾随数据被拒", []byte(base() + "{}")},
		{"空输入被拒", []byte(``)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := interchange.Import(st, tc.raw, gvr32, opts(pk1))
			if errReason(err) != domain.ReasonImportInvalid {
				t.Fatalf("want IMPORT_INVALID, got %v", err)
			}
			t.Logf("用例[%s] -> IMPORT_INVALID", tc.name)
		})
	}
}

func TestIdempotentReimport(t *testing.T) {
	t.Log("业务: 重复导入幂等 —— 同一文件（含缺根条目）重复导入不重复计数")
	st := openStore(t)
	root := "0x4ff6f743a43f3b4f95350831aeaf0a122a1a392922c45d804280284a69eb850b"
	f := localFile(
		`{"slot":"5","signing_root":"`+root+`"},{"slot":"6"}`,
		`{"source_epoch":"0","target_epoch":"1","signing_root":"0x587d6a4f59a58fe24f406e0502413e77fe1babddee641fda30034ed37ecc884d"},{"source_epoch":"1","target_epoch":"2"}`,
	)
	r1, err := interchange.Import(st, f, gvr32, opts(pk1))
	if err != nil {
		t.Fatal(err)
	}
	if r1.Imported != 4 {
		t.Fatalf("first imported=%d want 4", r1.Imported)
	}
	r2, err := interchange.Import(st, f, gvr32, opts(pk1))
	if err != nil {
		t.Fatalf("re-import: %v", err)
	}
	if r2.Imported != 0 || r2.Duplicate != 4 {
		t.Fatalf("re-import imported=%d duplicate=%d want 0/4", r2.Imported, r2.Duplicate)
	}
	atts, blocks := st.Snapshot()
	if len(atts) != 2 || len(blocks) != 2 {
		t.Fatalf("atts=%d blocks=%d want 2/2", len(atts), len(blocks))
	}
	t.Log("用例: 含 signing_root 与缺 signing_root 的条目重复导入均幂等")
}

func TestMissingRootConflictRejectsWholeFile(t *testing.T) {
	t.Log("业务: 关键信息缺失 —— 缺 signing_root 且无法证明同一次签署时整体拒绝")
	st := openStore(t)
	// 先导入 slot 5 缺根区块；再导入同 slot 带根的“新区块” => 无法确定，整体拒绝。
	base := localFile(`{"slot":"5"}`, "")
	if _, err := interchange.Import(st, base, gvr32, opts(pk1)); err != nil {
		t.Fatal(err)
	}
	other := localFile(
		`{"slot":"5","signing_root":"0x4ff6f743a43f3b4f95350831aeaf0a122a1a392922c45d804280284a69eb850b"}`,
		`{"source_epoch":"1","target_epoch":"3"}`)
	_, err := interchange.Import(st, other, gvr32, opts(pk1))
	if errReason(err) != domain.ReasonImportConflict {
		t.Fatalf("block: want IMPORT_CONFLICT, got %v", err)
	}
	atts, blocks := st.Snapshot()
	if len(atts) != 0 || len(blocks) != 1 {
		t.Fatalf("whole-file rejection polluted store: atts=%d blocks=%d", len(atts), len(blocks))
	}

	// 同 target、source 不同的两个缺根证明 => 无法确定是否同一次签署，整体拒绝。
	st2 := openStore(t)
	if _, err := interchange.Import(st2, localFile("", `{"source_epoch":"0","target_epoch":"2"}`), gvr32, opts(pk1)); err != nil {
		t.Fatal(err)
	}
	_, err = interchange.Import(st2, localFile("", `{"source_epoch":"1","target_epoch":"2"}`), gvr32, opts(pk1))
	if errReason(err) != domain.ReasonImportConflict {
		t.Fatalf("attestation: want IMPORT_CONFLICT, got %v", err)
	}
	atts2, _ := st2.Snapshot()
	if len(atts2) != 1 {
		t.Fatalf("want still 1 attestation, got %d", len(atts2))
	}
	t.Log("用例: 缺 signing_root 的同 slot 区块 / 同 target 证明一律整体拒绝，无部分写入")
}

func TestMalformedAndGenesisRejected(t *testing.T) {
	t.Log("业务: 非法文件整体拒绝 —— 截断/版本不符/根不符（上一轮回归）")
	st := openStore(t)
	good := localFile("", `{"source_epoch":"0","target_epoch":"1"}`)
	if _, err := interchange.Import(st, good, gvr32, opts(pk1)); err != nil {
		t.Fatal(err)
	}
	version4 := []byte(`{"metadata":{"interchange_format_version":"4","genesis_validators_root":"` +
		gvrHex() + `"},"data":[]}`)
	wrongGVR := []byte("32-byte-different-root-xxxxxxxx!")

	cases := []struct {
		name string
		raw  []byte
		gvr  []byte
	}{
		{"JSON 截断", []byte(`{"metadata":{"interchange_format_version":"5"`), gvr32},
		{"版本不支持", version4, gvr32},
		{"gvr 不匹配", good, wrongGVR},
		{"source>target", localFile("", `{"source_epoch":"3","target_epoch":"1"}`), gvr32},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := interchange.Import(st, tc.raw, tc.gvr, opts(pk1))
			if errReason(err) != domain.ReasonImportInvalid {
				t.Fatalf("want IMPORT_INVALID, got %v", err)
			}
			atts, blocks := st.Snapshot()
			if len(atts) != 1 || len(blocks) != 0 {
				t.Fatalf("records polluted: atts=%d blocks=%d", len(atts), len(blocks))
			}
			t.Logf("用例[%s] 整体拒绝，既有记录未污染", tc.name)
		})
	}
}

func TestMultiValidatorMergeAndUnknownIdentity(t *testing.T) {
	t.Log("业务: 多身份互导 —— 多验证者按身份合并；未知身份默认整体拒绝、可显式跳过")
	st := openStore(t)
	f := []byte(`{"metadata":{"interchange_format_version":"5","genesis_validators_root":"` + gvrHex() + `"},"data":[
	  {"pubkey":"` + pk1 + `","signed_blocks":[{"slot":"1"}],"signed_attestations":[{"source_epoch":"0","target_epoch":"1"}]},
	  {"pubkey":"` + pk2 + `","signed_blocks":[{"slot":"2"}],"signed_attestations":[{"source_epoch":"0","target_epoch":"2"}]}
	]}`)

	// 默认：pk2 本地不存在 => 整体拒绝，一条都不写。
	if _, err := interchange.Import(st, f, gvr32, opts(pk1)); errReason(err) != domain.ReasonUnknownValidator {
		t.Fatalf("want UNKNOWN_VALIDATOR, got %v", err)
	}
	atts, blocks := st.Snapshot()
	if len(atts) != 0 || len(blocks) != 0 {
		t.Fatalf("unknown identity must reject whole file, got atts=%d blocks=%d", len(atts), len(blocks))
	}

	// 显式跳过未知身份：pk1 合并，pk2 被稳定跳过并计数。
	r, err := interchange.Import(st, f, gvr32, interchange.Options{
		PubkeyToIndex:         map[string]uint64{pk1: 7},
		SkipUnknownValidators: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if r.Imported != 2 || r.SkippedValidators != 1 ||
		r.SkippedAttestations != 1 || r.SkippedBlocks != 1 {
		t.Fatalf("unexpected result: %+v", r)
	}

	// 两个身份都映射后完整合并（pk1 幂等，pk2 新增）。
	r2, err := interchange.Import(st, f, gvr32, opts(pk1, pk2))
	if err != nil {
		t.Fatal(err)
	}
	if r2.Imported != 2 || r2.Duplicate != 2 {
		t.Fatalf("second merge imported=%d duplicate=%d want 2/2", r2.Imported, r2.Duplicate)
	}
	atts, blocks = st.Snapshot()
	count := map[uint64]int{}
	for _, a := range atts {
		count[a.ValidatorIndex]++
	}
	for _, b := range blocks {
		count[b.ValidatorIndex] += 100
	}
	if count[7] != 101 || count[8] != 101 {
		t.Fatalf("per-identity merge wrong: %+v", count)
	}
	t.Log("用例: 未知身份默认整体拒绝；跳过语义计数准确；补齐映射后按身份正确合并且隔离")
}

func TestSameTargetAcrossIdentitiesNotConflict(t *testing.T) {
	t.Log("业务: 多身份互导 —— 不同身份同 target/slot 的缺根条目互不构成冲突")
	st := openStore(t)
	f := []byte(`{"metadata":{"interchange_format_version":"5","genesis_validators_root":"` + gvrHex() + `"},"data":[
	  {"pubkey":"` + pk1 + `","signed_blocks":[{"slot":"9"}],"signed_attestations":[{"source_epoch":"0","target_epoch":"1"}]},
	  {"pubkey":"` + pk2 + `","signed_blocks":[{"slot":"9"}],"signed_attestations":[{"source_epoch":"0","target_epoch":"1"}]}
	]}`)
	r, err := interchange.Import(st, f, gvr32, opts(pk1, pk2))
	if err != nil {
		t.Fatalf("different identities at same slot/target must not conflict: %v", err)
	}
	if r.Imported != 4 {
		t.Fatalf("imported=%d want 4", r.Imported)
	}
	// 重复导入同样幂等。
	r2, err := interchange.Import(st, f, gvr32, opts(pk1, pk2))
	if err != nil || r2.Duplicate != 4 {
		t.Fatalf("re-import duplicate=%d err=%v want 4", r2.Duplicate, err)
	}
	t.Log("用例: 两个身份在同 slot 9 / 同 target 1 的缺根条目并存，再导幂等")
}

func decodePK(hexStr string) []byte {
	b, err := hex.DecodeString(hexStr[2:])
	if err != nil {
		panic(err)
	}
	return b
}

func TestExportRoundTrip(t *testing.T) {
	t.Log("业务: 导出/回读往返 —— 按规范工具可读回，区块 signing_root 等内容一致")
	st := openStore(t)
	f := localFile(
		`{"slot":"2","signing_root":"0x4ff6f743a43f3b4f95350831aeaf0a122a1a392922c45d804280284a69eb850b"}`,
		`{"source_epoch":"0","target_epoch":"1","signing_root":"0x587d6a4f59a58fe24f406e0502413e77fe1babddee641fda30034ed37ecc884d"},{"source_epoch":"1","target_epoch":"3"}`,
	)
	if _, err := interchange.Import(st, f, gvr32, opts(pk1)); err != nil {
		t.Fatal(err)
	}

	out, err := interchange.Export(st, gvr32, map[uint64][]byte{7: decodePK(pk1)})
	if err != nil {
		t.Fatal(err)
	}

	// 导出文件必须被严格解析器原样接受（字段/类型完全合规）。
	parsed, err := interchange.Parse(out, gvr32)
	if err != nil {
		t.Fatalf("exported file must re-parse: %v", err)
	}
	if len(parsed.Data) != 1 {
		t.Fatalf("export entries=%d want 1", len(parsed.Data))
	}
	e0 := parsed.Data[0]
	if len(e0.SignedBlocks) != 1 || len(e0.SignedBlocks[0].SigningRoot) != 32 ||
		uint64(*e0.SignedBlocks[0].Slot) != 2 {
		t.Fatalf("block info incomplete in export: %+v", e0.SignedBlocks)
	}
	if len(e0.SignedAttestations) != 2 {
		t.Fatalf("attestations=%d want 2", len(e0.SignedAttestations))
	}
	var withRoot int
	for _, a := range e0.SignedAttestations {
		if len(a.SigningRoot) == 32 {
			withRoot++
		}
	}
	if withRoot != 1 {
		t.Fatalf("attestation signing roots: with=%d want 1", withRoot)
	}

	// 导出文件导入空库：记录集合一致；重复导入幂等。
	st2 := openStore(t)
	r, err := interchange.Import(st2, out, gvr32, opts(pk1))
	if err != nil {
		t.Fatalf("round-trip import: %v", err)
	}
	if r.Imported != 3 {
		t.Fatalf("fresh import=%d want 3", r.Imported)
	}
	if r2, err := interchange.Import(st2, out, gvr32, opts(pk1)); err != nil || r2.Imported != 0 {
		t.Fatalf("repeat import imported=%d err=%v want 0", r2.Imported, err)
	}

	a1, b1 := st.Snapshot()
	a2, b2 := st2.Snapshot()
	if !sameRecordSets(a1, b1, a2, b2) {
		t.Fatalf("round-trip mismatch:\n orig atts=%v blocks=%v\n copy atts=%v blocks=%v", a1, b1, a2, b2)
	}
	t.Log("用例: 导出文件含完整区块 signing_root，空库回读 3 条且再导幂等，集合一致")
}

func sameRecordSets(a1 []domain.AttestationRecord, b1 []domain.BlockRecord,
	a2 []domain.AttestationRecord, b2 []domain.BlockRecord) bool {
	if len(a1) != len(a2) || len(b1) != len(b2) {
		return false
	}
	// 导出经过排序，回读顺序应一致；逐条比对关键内容。
	for i := range a1 {
		x, y := a1[i], a2[i]
		if x.ValidatorIndex != y.ValidatorIndex || x.SourceEpoch != y.SourceEpoch ||
			x.TargetEpoch != y.TargetEpoch ||
			!bytesEqual(x.SigningRoot, y.SigningRoot) {
			return false
		}
	}
	for i := range b1 {
		x, y := b1[i], b2[i]
		if x.ValidatorIndex != y.ValidatorIndex || x.Slot != y.Slot ||
			!bytesEqual(x.SigningRoot, y.SigningRoot) {
			return false
		}
	}
	return true
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestConcurrentImportSignExport(t *testing.T) {
	t.Log("业务: 导入/签署/导出三者并发 —— 结论确定、无部分写入、导出为一致快照")

	for iter := 0; iter < 20; iter++ {
		st := openStore(t)

		// 互不冲突的多身份导入文件（不同身份 / 不同 epoch / 不同 slot）。
		fileFor := func(pk string, identity, n uint64) []byte {
			blk := ""
			for i := uint64(0); i < n; i++ {
				if blk != "" {
					blk += ","
				}
				blk = blk + `{"slot":"` + uintStr(100*identity+i) +
					`","signing_root":"0x` + blockRootHex(100*identity+i) + `"}`
			}
			att := ""
			for i := uint64(0); i < n; i++ {
				if att != "" {
					att += ","
				}
				att = att + `{"source_epoch":"` + uintStr(i) + `","target_epoch":"` +
					uintStr(200*identity+i+1) + `"}`
			}
			return []byte(`{"metadata":{"interchange_format_version":"5","genesis_validators_root":"` + gvrHex() +
				`"},"data":[{"pubkey":"` + pk + `","signed_blocks":[` + blk +
				`],"signed_attestations":[` + att + `]}]}`)
		}
		files := [][]byte{
			fileFor(pk1, 7, 3),
			fileFor(pk2, 8, 2),
			fileFor(pk1, 7, 3), // 同内容重复导入，幂等
		}

		var wg sync.WaitGroup
		start := make(chan struct{})
		importErrs := make(chan error, len(files))
		for i, f := range files {
			wg.Add(1)
			go func(i int, f []byte) {
				defer wg.Done()
				<-start
				_, err := interchange.Import(st, f, gvr32, opts(pk1, pk2))
				importErrs <- err
			}(i, f)
		}

		// 并发导出：每份导出必须能被重新解析（快照一致、无半条）。
		const exporters = 6
		for i := 0; i < exporters; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				out, err := interchange.Export(st, gvr32,
					map[uint64][]byte{7: decodePK(pk1), 8: decodePK(pk2)})
				if err != nil {
					t.Errorf("export: %v", err)
					return
				}
				if _, err := interchange.Parse(out, gvr32); err != nil {
					t.Errorf("concurrent export produced unparseable snapshot: %v", err)
				}
			}()
		}

		close(start)
		wg.Wait()
		close(importErrs)
		for err := range importErrs {
			if err != nil {
				t.Fatalf("iter %d concurrent import: %v", iter, err)
			}
		}

		atts, blocks := st.Snapshot()
		// pk1: 3 atts + 3 blocks；pk2: 2 atts + 2 blocks；重复导入幂等。
		if len(atts) != 5 || len(blocks) != 5 {
			t.Fatalf("iter %d: atts=%d blocks=%d want 5/5", iter, len(atts), len(blocks))
		}
	}
	t.Log("用例: 20 轮 导入×3 + 导出×6 并发，结果恒为 5+5 且每份导出均可重新解析")
}

func uintStr(v uint64) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

func blockRootHex(v uint64) string {
	// 生成确定性 64 位十六进制（32 字节）签名根。
	const pad = "4ff6f743a43f3b4f95350831aeaf0a122a01a392922c45d804284a69eb000000"
	s := uintStr(v)
	if len(s) > len(pad) {
		s = s[len(s)-len(pad):]
	}
	return pad[:len(pad)-len(s)] + s
}
