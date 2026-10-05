// Package chain 提供纯本地的信标链状态模拟：按确定性规则产生区块，
// 支持时间推进、链回退（reorg）与 finalized checkpoint 固化。
// 不依赖任何真实链数据、网络或外部服务。
package chain

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/lechandonga/validator-slashing-guard-go/internal/types"
)

// State 是本地模拟的链状态快照。
type State struct {
	GenesisValidatorsRoot types.Root `json:"genesis_validators_root"`
	CurrentSlot           uint64     `json:"current_slot"`
	FinalizedEpoch        uint64     `json:"finalized_epoch"`
	// Blocks 记录每个 slot 上当前规范链的区块根；空 slot 用零根表示。
	Blocks map[uint64]types.Root `json:"blocks"`
	// DutyDuties 记录本节点在各 slot 的职责来源根（模拟 beacon node 下发）。
	path string `json:"-"`
}

// LoadOrCreate 从 statePath 读取状态；文件不存在时以 genesis 初始化。
func LoadOrCreate(statePath string, validator types.ValidatorID) (*State, error) {
	s := &State{Blocks: map[uint64]types.Root{}, path: statePath}
	data, err := os.ReadFile(statePath)
	switch {
	case err == nil:
		if err := json.Unmarshal(data, s); err != nil {
			return nil, fmt.Errorf("parse chain state: %w", err)
		}
		if s.Blocks == nil {
			s.Blocks = map[uint64]types.Root{}
		}
		s.path = statePath
	case os.IsNotExist(err):
		s.GenesisValidatorsRoot = deterministicRoot("genesis-validators-root", validator[:])
		s.CurrentSlot = 0
		s.FinalizedEpoch = 0
		if err := s.persist(); err != nil {
			return nil, err
		}
	default:
		return nil, err
	}
	return s, nil
}

// Snapshot 返回状态的只读副本。
func (s *State) Snapshot() State {
	cp := State{
		GenesisValidatorsRoot: s.GenesisValidatorsRoot,
		CurrentSlot:           s.CurrentSlot,
		FinalizedEpoch:        s.FinalizedEpoch,
		Blocks:                make(map[uint64]types.Root, len(s.Blocks)),
	}
	for k, v := range s.Blocks {
		cp.Blocks[k] = v
	}
	return cp
}

// BlockRoot 返回规范链上指定 slot 的区块根；空 slot 返回零根与 false。
func (s *State) BlockRoot(slot uint64) (types.Root, bool) {
	r, ok := s.Blocks[slot]
	return r, ok && r != types.Root{}
}

// Advance 推进到下一个 slot，并确定性地产生一个新区块。
// 每跨过 FinalityEpochs(2) 个 epoch 边界，finalized epoch 前进一个 epoch，
// 模拟正常链上确定性最终性。
func (s *State) Advance() (uint64, types.Root, error) {
	s.CurrentSlot++
	root := deterministicRoot(fmt.Sprintf("canonical-slot-%d", s.CurrentSlot), s.GenesisValidatorsRoot[:])
	s.Blocks[s.CurrentSlot] = root
	newEpoch := types.EpochOf(s.CurrentSlot)
	// 进入新 epoch 且距 genesis 已超过 2 个 epoch 时，固化两个 epoch 前的检查点。
	if s.CurrentSlot%types.SlotsPerEpoch == 0 && newEpoch >= 2 {
		s.FinalizedEpoch = newEpoch - 2
	}
	if err := s.persist(); err != nil {
		return 0, types.Root{}, err
	}
	return s.CurrentSlot, root, nil
}

// Reorg 将链回退到 headSlot：严格小于 headSlot 之外的规范区块被移除，
// 并在 forkSlot 上放置一条竞争分叉块（与原规范链根不同）。
// finalized checkpoint 不可回退；请求回退到已最终化区间会被拒绝。
func (s *State) Reorg(headSlot, forkSlot uint64) (types.Root, error) {
	if forkSlot < s.FinalizedEpoch*types.SlotsPerEpoch {
		return types.Root{}, fmt.Errorf("cannot reorg slot %d below finalized epoch %d", forkSlot, s.FinalizedEpoch)
	}
	if headSlot > s.CurrentSlot {
		return types.Root{}, fmt.Errorf("head slot %d is ahead of current slot %d", headSlot, s.CurrentSlot)
	}
	for slot := range s.Blocks {
		if slot > headSlot {
			delete(s.Blocks, slot)
		}
	}
	s.CurrentSlot = headSlot
	fork := deterministicRoot(fmt.Sprintf("fork-slot-%d", forkSlot), s.GenesisValidatorsRoot[:])
	// 保证分叉根与任何可能存在的原规范根不同。
	if old, ok := s.Blocks[forkSlot]; ok && old == fork {
		fork[0] ^= 0xFF
	}
	s.Blocks[forkSlot] = fork
	if forkSlot > s.CurrentSlot {
		s.CurrentSlot = forkSlot
	}
	if err := s.persist(); err != nil {
		return types.Root{}, err
	}
	return fork, nil
}

func (s *State) persist() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(s.path, data)
}

func deterministicRoot(tag string, mix []byte) types.Root {
	h := sha256.New()
	h.Write([]byte(tag))
	h.Write(mix)
	var r types.Root
	copy(r[:], h.Sum(nil))
	return r
}

// atomicWrite 通过临时文件 + rename 保证单次状态写入要么完整可见、要么不可见。
func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
