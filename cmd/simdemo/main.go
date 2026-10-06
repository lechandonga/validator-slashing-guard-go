// Command simdemo 在本地完整模拟多个验证者同机运行：
// 链推进、多身份证明/区块签署、身份不匹配拒绝、并发重复触发、链回退、
// 崩溃重启与 EIP-3076 多身份记录互导。全程只使用本地生成的密钥与链状态，
// 不访问网络。
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"crypto/ed25519"
	"crypto/rand"

	"github.com/lechandonga/validator-slashing-guard-go/internal/domain"
	"github.com/lechandonga/validator-slashing-guard-go/internal/guard"
	"github.com/lechandonga/validator-slashing-guard-go/internal/interchange"
	"github.com/lechandonga/validator-slashing-guard-go/internal/simulator"
	"github.com/lechandonga/validator-slashing-guard-go/internal/store"
)

func main() {
	dir := flag.String("dir", filepath.Join(os.TempDir(), "vsg-demo"), "records directory")
	flag.Parse()
	if err := os.MkdirAll(*dir, 0o755); err != nil {
		log.Fatal(err)
	}
	recordsPath := filepath.Join(*dir, "records.json")

	gvr := []byte("local-genesis-validators-root!!!") // 32 字节，符合 EIP-3076 根长度
	state := domain.NewChainState(gvr, []byte{0x01, 0x00, 0x00, 0x00}, []byte("genesis-head"))
	sim := simulator.New(state)

	// 同一进程托管两个验证者身份（索引 / 公钥均不同）。
	const v1, v2 uint64 = 42, 43
	_, priv1, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	_, priv2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	val1 := guard.NewValidator(v1, priv1)
	val2 := guard.NewValidator(v2, priv2)

	st, err := store.Open(recordsPath)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	client := guard.NewClient(state, st, val1, val2)

	fmt.Println("== 多身份证明签名（slot 8）：各签各的，记录互相隔离 ==")
	for i := 0; i < 7; i++ {
		sim.Advance(v1, false)
	}
	duty1, _ := sim.Advance(v1, true)
	res1, err := client.SignAttestation(v1, duty1)
	fmt.Printf("validator=%d signed slot=%d target=%d err=%v\n", v1, duty1.Slot, duty1.TargetEpoch, err)

	duty2 := sim.AttestationFor(v2)
	_, err = client.SignAttestation(v2, duty2)
	fmt.Printf("validator=%d signed slot=%d target=%d err=%v\n", v2, duty2.Slot, duty2.TargetEpoch, err)

	fmt.Println("== 身份不匹配：用身份 v1 签署属于 v2 的职责 -> VALIDATOR_MISMATCH ==")
	_, err = client.SignAttestation(v1, duty2)
	fmt.Printf("mismatch err=%v\n", err)
	atts, _ := st.Snapshot()
	fmt.Printf("记录未被污染：attestations=%d（期望 2）\n", len(atts))

	fmt.Println("== 同一条已签职责并发重放 20 次：恰好 1 次成功 ==")
	var wg sync.WaitGroup
	var success, rejected int64
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := client.SignAttestation(v1, duty1); err == nil {
				atomic.AddInt64(&success, 1)
			} else {
				atomic.AddInt64(&rejected, 1)
			}
		}()
	}
	wg.Wait()
	fmt.Printf("success=%d rejected=%d（期望 success=0）\n", success, rejected)

	fmt.Println("== 多身份区块提议：同 slot 两个验证者各自可签；同人同 slot 不同区块被拒 ==")
	block1 := domain.BlockProposalRequest{
		Duty:       domain.Duty{ValidatorIndex: v1, Slot: 8},
		ParentRoot: []byte("parent-root-32-bytes-0000000000000000000"),
		StateRoot:  []byte("state-root-32-bytes-000000000000000000000"),
		BodyRoot:   []byte("body-root-32-bytes-0000000000000000000000"),
	}
	block2 := block1
	block2.ValidatorIndex = v2
	if _, err := client.SignBlock(v1, block1); err != nil {
		log.Fatalf("v1 block: %v", err)
	}
	if _, err := client.SignBlock(v2, block2); err != nil {
		log.Fatalf("v2 block: %v", err)
	}
	block1Alt := block1
	block1Alt.BodyRoot = []byte("other-body-root-32-bytes-000000000000000000")
	_, err = client.SignBlock(v1, block1Alt)
	fmt.Printf("same validator same slot different block err=%v\n", err)

	fmt.Println("== EIP-3076 多身份导出 / 再导入（幂等） ==")
	pubMap := map[uint64][]byte{v1: val1.PublicKey, v2: val2.PublicKey}
	exported, err := interchange.Export(st, gvr, pubMap)
	if err != nil {
		log.Fatal(err)
	}
	exportPath := filepath.Join(*dir, "interchange.json")
	if err := os.WriteFile(exportPath, exported, 0o600); err != nil {
		log.Fatal(err)
	}
	keyMap := map[string]uint64{
		interchange.PubkeyHex(val1.PublicKey): v1,
		interchange.PubkeyHex(val2.PublicKey): v2,
	}
	r, err := interchange.Import(st, exported, gvr, interchange.Options{PubkeyToIndex: keyMap})
	fmt.Printf("re-import: imported=%d duplicate=%d err=%v（期望 imported=0）\n", r.Imported, r.Duplicate, err)

	fmt.Println("== 重放签名与首次一致（确定性 / 崩溃恢复可解释） ==")
	replay, err := client.ReplaySignature(v1, res1.SigningRoot)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("deterministic replay identical=%v\n",
		string(replay.Signature) == string(res1.Signature))
	fmt.Printf("records file: %s\ninterchange file: %s\n", recordsPath, exportPath)
}
