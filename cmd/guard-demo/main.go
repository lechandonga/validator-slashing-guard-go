// guard-demo 在本地用确定性链状态完整演示：
//
//	正常证明/提议签署、并发重复触发、状态不匹配、链回退后的双重签署拦截、
//	EIP-3076 导出与冲突导入拒绝。
//
// 用法： go run ./cmd/guard-demo
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/lechandonga/validator-slashing-guard-go/internal/chain"
	"github.com/lechandonga/validator-slashing-guard-go/internal/interchange"
	"github.com/lechandonga/validator-slashing-guard-go/internal/signer"
	"github.com/lechandonga/validator-slashing-guard-go/internal/store"
	"github.com/lechandonga/validator-slashing-guard-go/internal/types"
)

func main() {
	dir := filepath.Join(".", ".demo-data")
	must(os.RemoveAll(dir))

	var validator types.ValidatorID
	validator[0] = 0xA1
	validator[47] = 0xB2

	ch, err := chain.LoadOrCreate(filepath.Join(dir, "chain-state.json"), validator)
	must(err)
	st, err := store.Open(dir, validator, ch.GenesisValidatorsRoot)
	must(err)
	defer st.Close()
	sg := signer.New(validator, ch, st)

	// 推进链到 epoch 2（slot 16），此时 finalized=0，epoch 2 的职责可签署。
	for ch.CurrentSlot < 16 {
		mustAdvance(ch)
	}

	fmt.Println("== 业务1：正常证明签署 ==")
	slot, blockRoot := mustAdvance(ch)
	signingRoot := rootTag("att", slot, blockRoot)
	duty := types.AttestationDuty{
		Validator: validator, Slot: slot, BeaconBlockRoot: blockRoot,
		TargetEpoch: types.EpochOf(slot), SourceEpoch: ch.FinalizedEpoch, SigningRoot: signingRoot,
	}
	sig, err := sg.SignAttestation(duty)
	must(err)
	fmt.Printf("  slot=%d 证明签署成功, 签名前缀=%x\n", slot, sig[:4])

	fmt.Println("== 业务2：同一条职责并发触发 10 次 ==")
	var wg sync.WaitGroup
	var ok, rejected int
	var mu sync.Mutex
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := sg.SignAttestation(duty)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				ok++
			} else {
				rejected++
			}
		}()
	}
	wg.Wait()
	fmt.Printf("  并发组内有效签署=%d（首次成功发生在业务1）, 重复拒绝=%d，全库记录数=%d\n",
		ok, rejected, len(st.Attestations()))

	fmt.Println("== 业务3：状态不匹配（伪造区块根）=")
	slot2, root2 := mustAdvance(ch)
	badRoot := root2
	badRoot[0] ^= 0xFF
	_, err = sg.SignAttestation(types.AttestationDuty{
		Validator: validator, Slot: slot2, BeaconBlockRoot: badRoot,
		TargetEpoch: types.EpochOf(slot2), SourceEpoch: ch.FinalizedEpoch,
		SigningRoot: rootTag("att", slot2, badRoot),
	})
	printReject(err)

	fmt.Println("== 业务4：区块提议与双重提议拦截 ==")
	ps, pr := mustAdvance(ch)
	prop := types.ProposalDuty{Validator: validator, Slot: ps, BlockRoot: pr, SigningRoot: rootTag("blk", ps, pr)}
	_, err = sg.SignProposal(prop)
	must(err)
	fmt.Printf("  slot=%d 提议签署成功\n", ps)
	_, err = sg.SignProposal(prop)
	printReject(err)

	fmt.Println("== 业务5：链状态回退后不撤销旧记录，并拦截同 epoch 不同内容证明 ==")
	forkRoot, err := ch.Reorg(slot2, slot2)
	must(err)
	_, err = sg.SignAttestation(types.AttestationDuty{
		Validator: validator, Slot: slot2, BeaconBlockRoot: forkRoot,
		TargetEpoch: types.EpochOf(slot2), SourceEpoch: ch.FinalizedEpoch,
		SigningRoot: rootTag("att-fork", slot2, forkRoot),
	})
	printReject(err)
	fmt.Printf("  回退后 head=%d finalizedEpoch=%d，历史证明记录数=%d（未被撤销）\n",
		ch.CurrentSlot, ch.FinalizedEpoch, len(st.Attestations()))

	fmt.Println("== 业务6：EIP-3076 导出、幂等再导入与冲突导入 ==")
	exported, err := interchange.Export(st, validator, ch.GenesisValidatorsRoot)
	must(err)
	exportPath := filepath.Join(dir, "interchange.json")
	must(os.WriteFile(exportPath, exported, 0o600))

	dir2 := filepath.Join(".", ".demo-data-imported")
	must(os.RemoveAll(dir2))
	ch2, err := chain.LoadOrCreate(filepath.Join(dir2, "chain-state.json"), validator)
	must(err)
	st2, err := store.Open(dir2, validator, ch2.GenesisValidatorsRoot)
	must(err)
	res, err := interchange.Import(exported, validator, ch2.GenesisValidatorsRoot, st2)
	must(err)
	fmt.Printf("  首次导入: 新增证明=%d 新增提议=%d\n", res.NewAttestations, res.NewProposals)
	res, err = interchange.Import(exported, validator, ch2.GenesisValidatorsRoot, st2)
	must(err)
	fmt.Printf("  再次导入(幂等): 新增证明=%d 新增提议=%d\n", res.NewAttestations, res.NewProposals)

	conflict := makeConflictExport(exported)
	_, err = interchange.Import(conflict, validator, ch2.GenesisValidatorsRoot, st2)
	printReject(err)
	fmt.Printf("  冲突导入后记录未被污染: 证明=%d 提议=%d\n", len(st2.Attestations()), len(st2.Proposals()))

	fmt.Println("演示完成，数据目录: .demo-data / .demo-data-imported")
}

func mustAdvance(ch *chain.State) (uint64, types.Root) {
	s, r, err := ch.Advance()
	must(err)
	return s, r
}

func rootTag(tag string, slot uint64, mix types.Root) types.Root {
	duty := types.AttestationDuty{Slot: slot, BeaconBlockRoot: mix}
	_ = duty
	var r types.Root
	copy(r[:8], []byte(tag))
	for i := 0; i < 8; i++ {
		r[i+8] = byte(slot >> (i * 8))
	}
	for i := 0; i < 24; i++ {
		r[i+8] ^= mix[i]
	}
	return r
}

func printReject(err error) {
	var ve *types.ValidationError
	if errors.As(err, &ve) {
		fmt.Printf("  已拒绝 原因=%s 说明=%s\n", ve.Reason, ve.Msg)
		return
	}
	panic(err)
}

// makeConflictExport 把导出文件中第一条证明的 signing_root 翻转，
// 制造“同 target epoch 不同内容”的冲突文件；GVR/pubkey 保持一致。
func makeConflictExport(original []byte) []byte {
	var f map[string]any
	mustJSON(original, &f)
	data := f["data"].([]any)
	vd := data[0].(map[string]any)
	atts := vd["signed_attestations"].([]any)
	a0 := atts[0].(map[string]any)
	sr := a0["signing_root"].(string)
	b := []byte(sr)
	if b[2] == '0' {
		b[2] = '1'
	} else {
		b[2] = '0'
	}
	a0["signing_root"] = string(b)
	out, err := jsonMarshal(f)
	must(err)
	return out
}

func mustJSON(raw []byte, v any) {
	must(json.Unmarshal(raw, v))
}

func jsonMarshal(v any) ([]byte, error) {
	return json.MarshalIndent(v, "", "  ")
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
