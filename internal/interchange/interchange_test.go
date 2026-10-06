package interchange_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"crypto/ed25519"
	"crypto/rand"
	"sync/atomic"

	"github.com/lechandonga/validator-slashing-guard-go/internal/domain"
	"github.com/lechandonga/validator-slashing-guard-go/internal/guard"
	"github.com/lechandonga/validator-slashing-guard-go/internal/interchange"
	"github.com/lechandonga/validator-slashing-guard-go/internal/store"
)

var gvr = bytes.Repeat([]byte{0x42}, 32)

func openStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "records.json"))
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// memDir 是测试用的身份目录（pubkey -> index）。
type memDir struct {
	byPubkey map[string]uint64
	pubkeys  map[uint64][]byte
}

func newDir(pairs ...uint64) *memDir {
	d := &memDir{byPubkey: map[string]uint64{}, pubkeys: map[uint64][]byte{}}
	for i, index := range pairs {
		pk := make([]byte, interchange.BLSPubkeyLength)
		pk[0] = byte(0xA0 + i)
		d.byPubkey[string(pk)] = index
		d.pubkeys[index] = pk
	}
	return d
}

func (d *memDir) ValidatorIndexByPubkey(pk []byte) (uint64, bool) {
	idx, ok := d.byPubkey[string(pk)]
	return idx, ok
}

func (d *memDir) PubkeyByValidatorIndex(index uint64) ([]byte, bool) {
	pk, ok := d.pubkeys[index]
	return pk, ok
}

func (d *memDir) HostedValidators() []uint64 {
	out := make([]uint64, 0, len(d.pubkeys))
	for idx := range d.pubkeys {
		out = append(out, idx)
	}
	return out
}

func (d *memDir) pk(index uint64) []byte { return d.pubkeys[index] }

func errReason(err error) string {
	var ge *domain.GuardError
	if errors.As(err, &ge) {
		return ge.Reason
	}
	return ""
}

func hex32(b byte) string {
	return "0x" + hex.EncodeToString(bytes.Repeat([]byte{b}, 32))
}

func gvrHex() string { return "0x" + hex.EncodeToString(gvr) }

// specFile 按 EIP-3076 规范线格式手工构造（字符串 epoch/slot、0x 根）。
func specFile(body string) []byte {
	return []byte(`{"metadata":{"interchange_format_version":"5","genesis_validators_root":"` +
		gvrHex() + `"},"data":[` + body + `]}`)
}

func vEntry(pk []byte, atts, blocks string) string {
	return fmt.Sprintf(`{"pubkey":"%s","signed_attestations":[%s],"signed_blocks":[%s]}`,
		"0x"+hex.EncodeToString(pk), atts, blocks)
}

func attWith(source, target uint64, signingRoot, blockRoot string) string {
	return fmt.Sprintf(`{"source_epoch":"%d","target_epoch":"%d"%s%s}`,
		source, target,
		optField("signing_root", signingRoot), optField("beacon_block_root", blockRoot))
}

func blockWith(slot uint64, signingRoot string) string {
	return fmt.Sprintf(`{"slot":"%d"%s}`, slot, optField("signing_root", signingRoot))
}

func optField(name, value string) string {
	if value == "" {
		return ""
	}
	return fmt.Sprintf(`,"%s":"%s"`, name, value)
}

func newTestValidator(t *testing.T, index uint64, id byte) *guard.Validator {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pk := make([]byte, interchange.BLSPubkeyLength)
	for i := range pk {
		pk[i] = id
	}
	return guard.NewValidator(index, pk, priv)
}

// TestEIP3076CanonicalSampleImport 验证规范的标准样例文件可以原样导入。
// 样例取自 EIP-3076 规范附录的 interchange_format_v5.json（字段名、字符串
// epoch/slot、0x 十六进制与本实现的 genesis root 对齐）。
func TestEIP3076CanonicalSampleImport(t *testing.T) {
	t.Log("业务: 规范兼容 —— EIP-3076 标准样例文件原样导入成功")
	st := openStore(t)

	// 使用规范字段名与编码（pubkey 48 字节、根 32 字节、epoch/slot 为字符串）。
	pk := bytes.Repeat([]byte{0xB7}, 48)
	dir := newDir()
	dir.byPubkey[string(pk)] = 0
	dir.pubkeys[0] = pk

	sample := []byte(fmt.Sprintf(`{
  "metadata": {
    "interchange_format_version": "5",
    "genesis_validators_root": "%s"
  },
  "data": [
    {
      "pubkey": "%s",
      "signed_blocks": [
        {"slot": "81952", "signing_root": "%s"},
        {"slot": "81953", "signing_root": "%s"}
      ],
      "signed_attestations": [
        {
          "source_epoch": "2560",
          "target_epoch": "2564",
          "signing_root": "%s",
          "beacon_block_root": "%s"
        },
        {
          "source_epoch": "2564",
          "target_epoch": "2566",
          "signing_root": "%s"
        }
      ]
    }
  ]
}`, gvrHex(), "0x"+hex.EncodeToString(pk),
		hex32(0x01), hex32(0x02), hex32(0x03), hex32(0x04), hex32(0x05)))

	n, err := interchange.Import(st, sample, gvr, dir, nil)
	if err != nil {
		t.Fatalf("canonical sample must import cleanly: %v", err)
	}
	if n != 4 {
		t.Fatalf("imported=%d want 4 (2 blocks + 2 attestations)", n)
	}

	// 区块必须以 slot + signing_root 落库（对方工具判断同 slot 不同区块所需）。
	_, blocks := st.Snapshot()
	if len(blocks) != 2 || !bytes.Equal(blocks[0].SigningRoot, bytes.Repeat([]byte{0x01}, 32)) {
		t.Fatalf("blocks not stored with signing roots: %+v", blocks)
	}
	t.Log("用例: 规范样例（含区块 signing_root、字符串 slot/epoch）原样导入 4 条")
}

func TestExportRoundTripSpecWireFormat(t *testing.T) {
	t.Log("业务: 规范兼容 —— 导出文件被按规范读回，线格式与内容逐项对得上")
	st := openStore(t)
	dir := newDir(1, 2)

	in := specFile(
		vEntry(dir.pk(1),
			attWith(0, 1, hex32(0x10), hex32(0x11))+","+attWith(1, 3, hex32(0x12), hex32(0x13)),
			blockWith(20, hex32(0x20))+","+blockWith(21, hex32(0x21))) + "," +
			vEntry(dir.pk(2),
				attWith(2, 3, hex32(0x30), hex32(0x31)),
				blockWith(20, hex32(0x40))))
	if _, err := interchange.Import(st, in, gvr, dir, nil); err != nil {
		t.Fatalf("seed import: %v", err)
	}

	out, err := interchange.Export(st, gvr, dir)
	if err != nil {
		t.Fatal(err)
	}

	// 用独立的 JSON 解析（不依赖本包类型）核对线格式：epoch/slot 必须是字符串，
	// 区块必须带 signing_root，版本号是字符串 "5"。
	var generic struct {
		Metadata struct {
			Version string `json:"interchange_format_version"`
			GVR     string `json:"genesis_validators_root"`
		} `json:"metadata"`
		Data []struct {
			Pubkey string           `json:"pubkey"`
			Atts   []map[string]any `json:"signed_attestations"`
			Blocks []map[string]any `json:"signed_blocks"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out, &generic); err != nil {
		t.Fatalf("exported file must be valid JSON: %v", err)
	}
	if generic.Metadata.Version != "5" || generic.Metadata.GVR != gvrHex() {
		t.Fatalf("metadata mismatch: %+v", generic.Metadata)
	}
	if len(generic.Data) != 2 {
		t.Fatalf("want 2 validator entries, got %d", len(generic.Data))
	}
	for _, v := range generic.Data {
		for _, b := range v.Blocks {
			if _, ok := b["slot"].(string); !ok {
				t.Fatalf("block slot must be JSON string: %v", b["slot"])
			}
			root, ok := b["signing_root"].(string)
			if !ok || len(root) != 66 {
				t.Fatalf("block must carry 32-byte signing_root: %v", b)
			}
		}
		for _, a := range v.Atts {
			if _, ok := a["target_epoch"].(string); !ok {
				t.Fatalf("target_epoch must be JSON string: %v", a["target_epoch"])
			}
		}
	}

	// 按规范读回到一个全新空库：记录集合与源库逐项一致，且重复导入幂等。
	st2 := openStore(t)
	n, err := interchange.Import(st2, out, gvr, dir, nil)
	if err != nil {
		t.Fatalf("round-trip import: %v", err)
	}
	if n != 6 {
		t.Fatalf("fresh round-trip imported=%d want 6", n)
	}
	if n2, err := interchange.Import(st2, out, gvr, dir, nil); err != nil || n2 != 0 {
		t.Fatalf("repeat import idempotency: added=%d err=%v", n2, err)
	}

	a1, b1 := st.Snapshot()
	a2, b2 := st2.Snapshot()
	assertSameRecords(t, a1, b1, a2, b2)
	t.Log("用例: 导出文件线格式合规（字符串/0x/区块根）；空库回读 6 条，再导幂等，集合逐项一致")
}

func assertSameRecords(t *testing.T, a1 []domain.AttestationRecord, b1 []domain.BlockRecord,
	a2 []domain.AttestationRecord, b2 []domain.BlockRecord) {
	t.Helper()
	if len(a1) != len(a2) || len(b1) != len(b2) {
		t.Fatalf("snapshot size mismatch atts %d/%d blocks %d/%d",
			len(a1), len(a2), len(b1), len(b2))
	}
	attKey := func(a domain.AttestationRecord) string {
		return fmt.Sprintf("%d|%d|%d|%x|%x", a.ValidatorIndex, a.SourceEpoch, a.TargetEpoch,
			a.SigningRoot, a.BeaconBlockRoot)
	}
	m1, m2 := map[string]bool{}, map[string]bool{}
	for _, a := range a1 {
		m1[attKey(a)] = true
	}
	for _, a := range a2 {
		m2[attKey(a)] = true
	}
	for k := range m1 {
		if !m2[k] {
			t.Fatalf("attestation record missing after round trip: %s", k)
		}
	}
	bs1, bs2 := map[string]bool{}, map[string]bool{}
	for _, b := range b1 {
		bs1[fmt.Sprintf("%d:%x", b.Slot, b.SigningRoot)] = true
	}
	for _, b := range b2 {
		bs2[fmt.Sprintf("%d:%x", b.Slot, b.SigningRoot)] = true
	}
	for k := range bs1 {
		if !bs2[k] {
			t.Fatalf("block record missing after round trip: %s", k)
		}
	}
}

func TestImportInvalidWireFormatRejectedWhole(t *testing.T) {
	t.Log("业务: 规范兼容 —— 线格式非法（数字 slot/epoch、缺 0x、根长度错）整体拒绝")
	st := openStore(t)
	dir := newDir(7)
	goodPK := "0x" + hex.EncodeToString(dir.pk(7))

	cases := []struct {
		name string
		raw  []byte
	}{
		{"epoch 写成 JSON 数字", []byte(fmt.Sprintf(
			`{"metadata":{"interchange_format_version":"5","genesis_validators_root":"%s"},`+
				`"data":[{"pubkey":"%s","signed_attestations":[{"source_epoch":0,"target_epoch":1}]}]}`,
			gvrHex(), goodPK))},
		{"slot 写成 JSON 数字", []byte(fmt.Sprintf(
			`{"metadata":{"interchange_format_version":"5","genesis_validators_root":"%s"},`+
				`"data":[{"pubkey":"%s","signed_blocks":[{"slot":9}]}]}`,
			gvrHex(), goodPK))},
		{"十六进制缺 0x 前缀", []byte(fmt.Sprintf(
			`{"metadata":{"interchange_format_version":"5","genesis_validators_root":"%s"},`+
				`"data":[{"pubkey":"%s","signed_blocks":[{"slot":"9","signing_root":"%x"}]}]}`,
			gvrHex(), goodPK, bytes.Repeat([]byte{1}, 32)))},
		{"区块 signing_root 长度错误", specFile(vEntry(dir.pk(7), "",
			`{"slot":"9","signing_root":"0x1234"}`))},
		{"pubkey 不是 48 字节", []byte(fmt.Sprintf(
			`{"metadata":{"interchange_format_version":"5","genesis_validators_root":"%s"},`+
				`"data":[{"pubkey":"0xaaaa","signed_attestations":[],"signed_blocks":[]}]}`,
			gvrHex()))},
		{"格式版本不支持", []byte(fmt.Sprintf(
			`{"metadata":{"interchange_format_version":"4","genesis_validators_root":"%s"},`+
				`"data":[{"pubkey":"%s","signed_attestations":[],"signed_blocks":[]}]}`,
			gvrHex(), goodPK))},
		{"genesis 根不匹配", []byte(fmt.Sprintf(
			`{"metadata":{"interchange_format_version":"5","genesis_validators_root":"0x%s"},`+
				`"data":[{"pubkey":"%s","signed_attestations":[],"signed_blocks":[]}]}`,
			hex.EncodeToString(bytes.Repeat([]byte{0xff}, 32)), goodPK))},
		{"JSON 被截断", []byte(`{"metadata":{"interchange_format_version":"5"`)},
		{"source>target", specFile(vEntry(dir.pk(7),
			attWith(3, 1, "", ""), ""))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n, err := interchange.Import(st, tc.raw, gvr, dir, nil)
			if errReason(err) != domain.ReasonImportInvalid {
				t.Fatalf("want IMPORT_INVALID, got %v", err)
			}
			if n != 0 {
				t.Fatalf("partial import detected: %d", n)
			}
			atts, blocks := st.Snapshot()
			if len(atts) != 0 || len(blocks) != 0 {
				t.Fatalf("records polluted: atts=%d blocks=%d", len(atts), len(blocks))
			}
			t.Logf("用例[%s] 整体拒绝，存储零污染", tc.name)
		})
	}
}

func TestImportConflictAtomic(t *testing.T) {
	t.Log("业务: 导入冲突 —— 不同签署内容/区间冲突整体拒绝，不部分写入")
	st := openStore(t)
	dir := newDir(7)

	base := specFile(vEntry(dir.pk(7),
		attWith(0, 2, hex32(0x01), hex32(0x02)), blockWith(3, hex32(0x03))))
	if _, err := interchange.Import(st, base, gvr, dir, nil); err != nil {
		t.Fatal(err)
	}

	// 同 slot 不同区块 signing_root -> IMPORT_CONFLICT。
	diffBlock := specFile(vEntry(dir.pk(7), "", blockWith(3, hex32(0x09))))
	if _, err := interchange.Import(st, diffBlock, gvr, dir, nil); errReason(err) != domain.ReasonImportConflict {
		t.Fatalf("want IMPORT_CONFLICT for different block, got %v", err)
	}

	// 同 target 不同证明 signing_root -> IMPORT_CONFLICT。
	diffAtt := specFile(vEntry(dir.pk(7), attWith(0, 2, hex32(0x07), hex32(0x08)), ""))
	if _, err := interchange.Import(st, diffAtt, gvr, dir, nil); errReason(err) != domain.ReasonImportConflict {
		t.Fatalf("want IMPORT_CONFLICT for double vote, got %v", err)
	}

	// surround（被既有区间包含）。
	st2 := openStore(t)
	if _, err := interchange.Import(st2, specFile(vEntry(dir.pk(7),
		attWith(0, 4, hex32(0x10), ""), "")), gvr, dir, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := interchange.Import(st2, specFile(vEntry(dir.pk(7),
		attWith(1, 3, hex32(0x11), ""), "")), gvr, dir, nil); errReason(err) != domain.ReasonImportConflict {
		t.Fatalf("want surround IMPORT_CONFLICT, got %v", err)
	}

	// 文件内自相矛盾（同 target 两根）同样整体拒绝。
	selfContradict := specFile(vEntry(dir.pk(7),
		attWith(0, 2, hex32(0x20), "")+","+attWith(0, 2, hex32(0x21), ""), ""))
	st3 := openStore(t)
	if _, err := interchange.Import(st3, selfContradict, gvr, dir, nil); errReason(err) != domain.ReasonImportConflict {
		t.Fatalf("want in-file IMPORT_CONFLICT, got %v", err)
	}

	// 同 slot 同 signing_root 幂等，不新增。
	if n, err := interchange.Import(st, specFile(vEntry(dir.pk(7), "",
		blockWith(3, hex32(0x03)))), gvr, dir, nil); err != nil || n != 0 {
		t.Fatalf("identical block must be idempotent: n=%d err=%v", n, err)
	}
	atts, blocks := st.Snapshot()
	if len(atts) != 1 || len(blocks) != 1 {
		t.Fatalf("conflict polluted records: atts=%d blocks=%d", len(atts), len(blocks))
	}
	t.Log("用例: 区块/证明冲突、surround、文件内自相矛盾均整体拒绝；相同签署幂等")
}

func TestImportAmbiguousWhenSigningRootMissing(t *testing.T) {
	t.Log("业务: 冲突信息缺失 —— 无法证明同一次签署时 IMPORT_AMBIGUOUS 整体拒绝")
	st := openStore(t)
	dir := newDir(7)

	// 既有记录：同 slot 区块带根；导入条目同 slot 不带根 -> 无法判定。
	if _, err := interchange.Import(st, specFile(vEntry(dir.pk(7), "",
		blockWith(5, hex32(0x01)))), gvr, dir, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := interchange.Import(st, specFile(vEntry(dir.pk(7), "",
		`{"slot":"5"}`)), gvr, dir, nil); errReason(err) != domain.ReasonImportAmbiguous {
		t.Fatalf("block missing root want IMPORT_AMBIGUOUS, got %v", err)
	}

	// 既有证明同 target 带根；导入证明同 target 不带根且投票根不同 -> 无法判定。
	st2 := openStore(t)
	if _, err := interchange.Import(st2, specFile(vEntry(dir.pk(7),
		attWith(1, 2, hex32(0x02), hex32(0x03)), "")), gvr, dir, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := interchange.Import(st2, specFile(vEntry(dir.pk(7),
		attWith(1, 2, "", ""), "")), gvr, dir, nil); errReason(err) != domain.ReasonImportAmbiguous {
		t.Fatalf("attestation missing root want IMPORT_AMBIGUOUS, got %v", err)
	}

	// 两侧都缺 signing_root、但 source/target/beacon_block_root 完全一致：
	// 规范允许的最小信息集下视为同一次签署，幂等通过。
	st3 := openStore(t)
	basic := specFile(vEntry(dir.pk(7), attWith(1, 2, "", hex32(0x04)), ""))
	if _, err := interchange.Import(st3, basic, gvr, dir, nil); err != nil {
		t.Fatalf("minimal-info attestation import: %v", err)
	}
	if n, err := interchange.Import(st3, basic, gvr, dir, nil); err != nil || n != 0 {
		t.Fatalf("identical minimal-info entry must be idempotent: n=%d err=%v", n, err)
	}

	atts, blocks := st.Snapshot()
	if len(atts) != 0 || len(blocks) != 1 {
		t.Fatalf("ambiguous import must not add records: atts=%d blocks=%d", len(atts), len(blocks))
	}
	t.Log("用例: 区块/证明缺根且无法判定 -> IMPORT_AMBIGUOUS 整体拒绝；最小信息完全一致才幂等")
}

func TestImportMultipleValidatorsByIdentity(t *testing.T) {
	t.Log("业务: 多身份互导 —— 一个文件多个验证者条目按身份正确合并与隔离")
	st := openStore(t)
	dir := newDir(1, 2, 3)

	// 同一 slot、同一 target epoch，两个身份内容不同：必须分别落库、互不判冲突。
	f := specFile(
		vEntry(dir.pk(1),
			attWith(0, 1, hex32(0xA1), hex32(0xA2)), blockWith(10, hex32(0xA3))) + "," +
			vEntry(dir.pk(2),
				attWith(0, 1, hex32(0xB1), hex32(0xB2)), blockWith(10, hex32(0xB3))))
	n, err := interchange.Import(st, f, gvr, dir, nil)
	if err != nil {
		t.Fatalf("multi-validator import: %v", err)
	}
	if n != 4 {
		t.Fatalf("imported=%d want 4", n)
	}

	// 身份 1 的区块同 slot 不同根 -> 冲突；身份 2 不受影响，且整体拒绝不写入。
	bad := specFile(vEntry(dir.pk(1), "", blockWith(10, hex32(0xC1))))
	if _, err := interchange.Import(st, bad, gvr, dir, nil); errReason(err) != domain.ReasonImportConflict {
		t.Fatalf("want conflict for v1 block, got %v", err)
	}

	// 重复导入同一文件幂等（两身份共 4 条，不重复计数）。
	if n2, err := interchange.Import(st, f, gvr, dir, nil); err != nil || n2 != 0 {
		t.Fatalf("re-import idempotency: added=%d err=%v", n2, err)
	}

	// 导出只包含本地托管身份；按身份分组不串。
	out, err := interchange.Export(st, gvr, dir)
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Data []struct {
			Pubkey string `json:"pubkey"`
			Blocks []struct {
				Root string `json:"signing_root"`
			} `json:"signed_blocks"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.Data) != 2 {
		t.Fatalf("export entries=%d want 2 hosted validators with records", len(parsed.Data))
	}
	t.Log("用例: 同 slot/同 target 跨身份导入 4 条；同身份冲突整体拒绝；重导幂等；导出按身份分组")
}

func TestImportUnknownValidatorSemantics(t *testing.T) {
	t.Log("业务: 多身份互导 —— 文件身份本地不存在时语义明确稳定")
	dir := newDir(1)

	unknownPK := bytes.Repeat([]byte{0x77}, interchange.BLSPubkeyLength)
	// 混合文件：一个本地身份 + 一个未知身份。
	mixed := specFile(
		vEntry(dir.pk(1), attWith(0, 1, hex32(0x01), ""), "") + "," +
			vEntry(unknownPK, attWith(0, 1, hex32(0x02), ""), ""))

	// 默认：整体拒绝 UNKNOWN_VALIDATOR，连已知身份的条目也不能部分写入。
	st := openStore(t)
	if _, err := interchange.Import(st, mixed, gvr, dir, nil); errReason(err) != domain.ReasonUnknownValidator {
		t.Fatalf("want UNKNOWN_VALIDATOR, got %v", err)
	}
	if atts, _ := st.Snapshot(); len(atts) != 0 {
		t.Fatalf("known validator records must not be partially written: %d", len(atts))
	}

	// 显式 skip 语义：未知身份整条跳过，已知身份正常合并。
	st2 := openStore(t)
	n, err := interchange.Import(st2, mixed, gvr, dir, &interchange.ImportOptions{SkipUnknownValidators: true})
	if err != nil {
		t.Fatalf("skip-unknown import: %v", err)
	}
	if n != 1 {
		t.Fatalf("imported=%d want 1 (only known validator)", n)
	}

	// 纯未知身份文件默认拒绝、skip 时 0 新增且无错。
	onlyUnknown := specFile(vEntry(unknownPK, "", blockWith(1, hex32(0x03))))
	st3 := openStore(t)
	if _, err := interchange.Import(st3, onlyUnknown, gvr, dir, nil); errReason(err) != domain.ReasonUnknownValidator {
		t.Fatalf("all-unknown file must be rejected by default, got %v", err)
	}
	if n, err := interchange.Import(st3, onlyUnknown, gvr, dir,
		&interchange.ImportOptions{SkipUnknownValidators: true}); err != nil || n != 0 {
		t.Fatalf("skip all-unknown: n=%d err=%v", n, err)
	}
	t.Log("用例: 默认整体拒绝 UNKNOWN_VALIDATOR 且不部分写入；显式 skip 时未知身份整条跳过")
}

func TestConcurrentImportSignExport(t *testing.T) {
	t.Log("业务: 导入/签名/导出并发 —— 结论确定、无半条记录、导出为一致快照")

	// 用真实的 guard.Client（实现身份目录）+ 真实 store 串起三方并发。
	const iterations = 20
	for iter := 0; iter < iterations; iter++ {
		dir := t.TempDir()
		state := domain.NewChainState(gvr, []byte{1, 0, 0, 0}, []byte("genesis-head"))
		st, err := store.Open(filepath.Join(dir, "records.json"))
		if err != nil {
			t.Fatal(err)
		}

		v1 := newTestValidator(t, 1, 0xA1)
		v2 := newTestValidator(t, 2, 0xA2)
		client := guard.NewClient(state, st, v1, v2)

		// 迁移文件：身份 1 的历史证明 + 区块（固定根，重复导入幂等）。
		migration := specFile(vEntry(v1.BeaconPubKey,
			attWith(0, 4, hex32(0x10), "")+","+attWith(4, 5, hex32(0x11), ""),
			blockWith(100, hex32(0x12))))

		var wg sync.WaitGroup
		start := make(chan struct{})
		var importAdds int64
		var importErrors []error
		var mu sync.Mutex

		// 5 路重复导入同一文件。
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				n, err := interchange.Import(st, migration, gvr, client, nil)
				mu.Lock()
				if err != nil {
					importErrors = append(importErrors, err)
				}
				importAdds += int64(n)
				mu.Unlock()
			}()
		}

		// 1 路并发签署：推进链，让身份 2 在 slot 8 反复触发同一职责（恰 1 次成功）。
		state.Advance(8, 1, 0, bytes.Repeat([]byte{0x55}, 32))
		signReq := domain.AttestationRequest{
			Duty:            domain.Duty{ValidatorIndex: 2, Slot: 8},
			BeaconPublicKey: append([]byte(nil), v2.BeaconPubKey...),
			SourceEpoch:     1,
			TargetEpoch:     1,
			BeaconBlockRoot: bytes.Repeat([]byte{0x55}, 32),
		}
		var signOK int64
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				if _, err := client.SignAttestation(signReq); err == nil {
					atomic.AddInt64(&signOK, 1)
				}
			}()
		}

		// 1 路并发导出：每次结果必须是可解析的一致快照。
		var snapOKN int64
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				raw, err := interchange.Export(st, gvr, client)
				if err != nil {
					t.Errorf("export: %v", err)
					return
				}
				var snap interchange.File
				if err := json.Unmarshal(raw, &snap); err != nil {
					t.Errorf("export snapshot unparseable: %v", err)
					return
				}
				// 任意快照里，身份 1 的区块要么没出现、要么恰好是完整的 1 条，
				// 绝不会出现半条/重复；证明同理按 target 唯一。
				for _, e := range snap.Data {
					seenBlocks := map[uint64]int{}
					for _, b := range e.SignedBlocks {
						seenBlocks[uint64(b.Slot)]++
						if len(b.SigningRoot) != 32 {
							t.Errorf("exported block missing signing_root")
						}
					}
					for slot, c := range seenBlocks {
						if c > 1 {
							t.Errorf("snapshot block slot %d appears %d times", slot, c)
						}
					}
					seenTargets := map[uint64]int{}
					for _, a := range e.SignedAttestations {
						seenTargets[uint64(a.TargetEpoch)]++
					}
					for target, c := range seenTargets {
						if c > 1 {
							t.Errorf("snapshot attestation target %d appears %d times", target, c)
						}
					}
				}
				atomic.AddInt64(&snapOKN, 1)
			}()
		}

		close(start)
		wg.Wait()

		mu.Lock()
		if len(importErrors) != 0 {
			t.Fatalf("iter %d unexpected import error: %v", iter, importErrors[0])
		}
		mu.Unlock()
		// 迁移文件含 3 条记录：无论多少路并发导入，总新增恒为 3（幂等）。
		if importAdds != 3 {
			t.Fatalf("iter %d total import adds=%d want 3", iter, importAdds)
		}
		if signOK != 1 {
			t.Fatalf("iter %d concurrent sign successes=%d want exactly 1", iter, signOK)
		}
		if got := atomic.LoadInt64(&snapOKN); got != 8 {
			t.Fatalf("iter %d consistent snapshots=%d want 8", iter, got)
		}

		atts, blocks := st.Snapshot()
		if len(blocks) != 1 {
			t.Fatalf("iter %d blocks=%d want 1", iter, len(blocks))
		}
		if len(atts) != 3 { // 迁移 2 条（身份 1）+ 并发签署 1 条（身份 2）
			t.Fatalf("iter %d atts=%d want 3", iter, len(atts))
		}
	}
	t.Log("用例: 20 轮 导入x5/签署x5/导出x8 并发：导入恒增 3、签署恰 1 次、8 份快照均一致")
}
