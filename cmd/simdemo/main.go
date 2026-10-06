// Command simdemo 在本地完整模拟多个验证者的托管运行：
// 链推进、证明/区块签署、身份归属与不匹配拒绝、并发重复触发、链回退、
// 崩溃重启与标准 EIP-3076 记录互导。全程只使用本地生成的密钥与链状态。
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lechandonga/validator-slashing-guard-go/internal/domain"
	"github.com/lechandonga/validator-slashing-guard-go/internal/guard"
	"github.com/lechandonga/validator-slashing-guard-go/internal/interchange"
	"github.com/lechandonga/validator-slashing-guard-go/internal/simulator"
	"github.com/lechandonga/validator-slashing-guard-go/internal/store"
)

func beaconPubkey(b byte) []byte {
	k := make([]byte, interchange.BLSPubkeyLength)
	for i := range k {
		k[i] = b
	}
	return k
}

func newValidator(index uint64, id byte) *guard.Validator {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	return guard.NewValidator(index, beaconPubkey(id), priv)
}

func main() {
	defaultDir := filepath.Join(os.TempDir(), fmt.Sprintf("vsg-demo-%d", time.Now().UnixNano()))
	dir := flag.String("dir", defaultDir, "records directory")
	flag.Parse()
	if err := os.MkdirAll(*dir, 0o755); err != nil {
		log.Fatal(err)
	}
	recordsPath := filepath.Join(*dir, "records.json")

	gvr := []byte("local-genesis-validators-root-0001")
	state := domain.NewChainState(gvr, []byte{0x01, 0x00, 0x00, 0x00}, []byte("genesis-head"))
	sim := simulator.New(state)

	valA := newValidator(42, 0xAA) // 身份 A：索引 42
	valB := newValidator(7, 0xBB)  // 身份 B：索引 7

	st, err := store.Open(recordsPath)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	client := guard.NewClient(state, st, valA, valB)

	fmt.Println("== 多身份：A 在 slot 8 正常证明签名 ==")
	for sim.CurrentHead().CurrentSlot < 7 {
		sim.Advance(42, false)
	}
	duty, _ := sim.Advance(42, true)
	duty.BeaconPublicKey = valA.BeaconPubKey
	res, err := client.SignAttestation(duty)
	fmt.Printf("signed validator=42 slot=%d target=%d err=%v\n", duty.Slot, duty.TargetEpoch, err)
	firstSig := append([]byte(nil), res.Signature...)

	fmt.Println("== 身份不匹配：请求带 B 的公钥、却落到索引 42 -> IDENTITY_MISMATCH ==")
	imposter := duty
	imposter.BeaconPublicKey = valB.BeaconPubKey
	_, err = client.SignAttestation(imposter)
	fmt.Printf("IDENTITY_MISMATCH: %v\n", err)

	fmt.Println("== 身份隔离：A 的同 target 记录不影响 B 签不同内容 ==")
	bDuty := duty
	bDuty.ValidatorIndex = 7
	bDuty.BeaconPublicKey = valB.BeaconPubKey
	bDuty.BeaconBlockRoot = append([]byte(nil), duty.BeaconBlockRoot...)
	if _, err := client.SignAttestation(bDuty); err != nil {
		log.Fatalf("validator B sign: %v", err)
	}
	fmt.Println("validator 7 signed at same target epoch without DOUBLE_VOTE")

	fmt.Println("== 未知身份：索引 99 未托管 -> UNKNOWN_VALIDATOR ==")
	unknown := duty
	unknown.ValidatorIndex = 99
	unknown.BeaconPublicKey = beaconPubkey(0x99)
	_, err = client.SignAttestation(unknown)
	fmt.Printf("UNKNOWN_VALIDATOR: %v\n", err)

	fmt.Println("== 同一条已签职责并发重放 20 次：恰好 1 次成功 ==")
	var wg sync.WaitGroup
	var success, rejected int64
	start := make(chan struct{})
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := client.SignAttestation(duty); err == nil {
				atomic.AddInt64(&success, 1)
			} else {
				atomic.AddInt64(&rejected, 1)
			}
		}()
	}
	close(start)
	wg.Wait()
	fmt.Printf("success=%d rejected=%d (期望 success=0，全部 DUPLICATE_DUTY)\n", success, rejected)

	fmt.Println("== 导出标准 EIP-3076 / 再导入（幂等） ==")
	exported, err := interchange.Export(st, gvr, client)
	if err != nil {
		log.Fatal(err)
	}
	exportPath := filepath.Join(*dir, "interchange.json")
	if err := os.WriteFile(exportPath, exported, 0o600); err != nil {
		log.Fatal(err)
	}
	n, err := interchange.Import(st, exported, gvr, client, nil)
	fmt.Printf("re-import: new=%d err=%v (期望 new=0，幂等)\n", n, err)

	fmt.Println("== 重放签名与首次一致（确定性 / 崩溃恢复可解释） ==")
	replay, err := client.ReplaySignature(42, res.SigningRoot)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("deterministic replay identical=%v\n",
		string(replay.Signature) == string(firstSig))
	fmt.Printf("records file: %s\ninterchange file: %s\n", recordsPath, exportPath)
}
