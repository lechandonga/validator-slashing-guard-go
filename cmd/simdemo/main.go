// Command simdemo 在本地完整模拟一个验证者的运行：
// 链推进、证明/区块签署、并发重复触发、链回退、崩溃重启与记录互导。
// 全程只使用本地生成的密钥与链状态，不访问网络。
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

	gvr := []byte("local-genesis-validators-root-0001")
	state := domain.NewChainState(gvr, []byte{0x01, 0x00, 0x00, 0x00}, []byte("genesis-head"))
	sim := simulator.New(state)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	_ = pub
	const validatorIndex uint64 = 42
	val := guard.NewValidator(validatorIndex, priv)
	pubHex := fmt.Sprintf("0x%x", []byte(pub))

	st, err := store.Open(recordsPath)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	client := guard.NewClient(state, st, val)

	fmt.Println("== 正常证明签名（slot 8） ==")
	for i := 0; i < 7; i++ {
		sim.Advance(validatorIndex, false)
	}
	duty, _ := sim.Advance(validatorIndex, true)
	res, err := client.SignAttestation(duty)
	fmt.Printf("signed slot=%d target=%d err=%v\n", duty.Slot, duty.TargetEpoch, err)
	firstSig := append([]byte(nil), res.Signature...)

	fmt.Println("== 准入拒绝原因可区分（链停留在 slot 8） ==")
	mismatch := duty
	mismatch.BeaconBlockRoot = []byte("another-chain-head-root-32bytes!")
	_, err = client.SignAttestation(mismatch)
	fmt.Printf("STATE_MISMATCH: %v\n", err)

	expired := duty
	// slot 7 已过期（target epoch 与 slot 匹配的情况下被 DUTY_EXPIRED 拒绝）
	expired.Slot = 7
	expired.TargetEpoch = domain.EpochOf(7)
	expired.SourceEpoch = 0
	expired.BeaconBlockRoot = duty.BeaconBlockRoot
	_, err = client.SignAttestation(expired)
	fmt.Printf("DUTY_EXPIRED:  %v\n", err)

	future := duty
	future.Slot = 9
	future.TargetEpoch = domain.EpochOf(9)
	_, err = client.SignAttestation(future)
	fmt.Printf("DUTY_FUTURE:   %v\n", err)

	fmt.Println("== 同一条已签职责并发重放 20 次：全部 DUPLICATE_DUTY 拒绝 ==")
	var wg sync.WaitGroup
	var success, rejected int64
	var reasons sync.Map
	var mu sync.Mutex
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := client.SignAttestation(duty)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				success++
			} else {
				rejected++
				if ge, ok := err.(*domain.DuplicateError); ok {
					reasons.Store(ge.Reason, struct{}{})
				}
			}
		}()
	}
	wg.Wait()
	fmt.Printf("success=%d rejected=%d (期望 success=0)\n", success, rejected)

	fmt.Println("== 全新职责并发触发 20 次：恰好 1 次成功 ==")
	for i := 0; i < 8; i++ {
		sim.Advance(validatorIndex, false)
	}
	freshDuty, _ := sim.Advance(validatorIndex, true)
	var wg2 sync.WaitGroup
	var ok2, no2 int64
	for i := 0; i < 20; i++ {
		wg2.Add(1)
		go func() {
			defer wg2.Done()
			if _, err := client.SignAttestation(freshDuty); err == nil {
				atomic.AddInt64(&ok2, 1)
			} else {
				atomic.AddInt64(&no2, 1)
			}
		}()
	}
	wg2.Wait()
	fmt.Printf("success=%d rejected=%d (期望 success=1)\n", ok2, no2)

	fmt.Println("== 链回退后旧记录仍在，过期职责被拒 ==")
	if err := sim.Rollback(8, 1, 0); err != nil {
		log.Fatal(err)
	}
	_, err = client.SignAttestation(duty)
	fmt.Printf("after rollback re-sign err=%v\n", err)
	sim.Advance(validatorIndex, false)
	atts, blocks := st.Snapshot()
	fmt.Printf("records preserved across rollback: attestations=%d blocks=%d\n", len(atts), len(blocks))

	fmt.Println("== 导出 / 再导入（幂等） ==")
	exported, err := interchange.Export(st, gvr, map[uint64]string{validatorIndex: pubHex})
	if err != nil {
		log.Fatal(err)
	}
	exportPath := filepath.Join(*dir, "interchange.json")
	if err := os.WriteFile(exportPath, exported, 0o600); err != nil {
		log.Fatal(err)
	}
	n, err := interchange.Import(st, exported, gvr, map[string]uint64{pubHex: validatorIndex})
	fmt.Printf("re-import: new=%d err=%v (期望 new=0，幂等)\n", n, err)

	fmt.Println("== 重放签名与首次一致（确定性 / 崩溃恢复可解释） ==")
	replay := client.ReplaySignature(res.SigningRoot)
	fmt.Printf("deterministic replay identical=%v\n",
		string(replay.Signature) == string(firstSig))
	fmt.Printf("records file: %s\ninterchange file: %s\n", recordsPath, exportPath)
}
