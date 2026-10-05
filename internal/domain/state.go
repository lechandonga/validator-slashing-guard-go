package domain

import (
	"crypto/sha256"
	"sync"
)

// SlotsPerEpoch 是本地模拟链使用的常数（主网为 32，本地缩小便于观察跨 epoch）。
const SlotsPerEpoch uint64 = 8

// ChainHead 是链状态在某一时刻的不可变快照。
type ChainHead struct {
	CurrentSlot           uint64
	HeadRoot              []byte
	JustifiedEpoch        uint64
	FinalizedEpoch        uint64
	ForkVersion           []byte
	GenesisValidatorsRoot []byte
}

// ChainState 是本地模拟的链状态，可被推进（Advance）或回退（Rollback）。
// 它与签名记录存储彼此独立：回退链状态不会改动任何已固化记录。
type ChainState struct {
	mu sync.RWMutex
	h  ChainHead
}

func NewChainState(genesisValidatorsRoot, forkVersion, genesisHeadRoot []byte) *ChainState {
	cs := &ChainState{}
	cs.h = ChainHead{
		CurrentSlot:           0,
		HeadRoot:              append([]byte(nil), genesisHeadRoot...),
		JustifiedEpoch:        0,
		FinalizedEpoch:        0,
		ForkVersion:           append([]byte(nil), forkVersion...),
		GenesisValidatorsRoot: append([]byte(nil), genesisValidatorsRoot...),
	}
	return cs
}

// Snapshot 返回当前链头的拷贝。
func (c *ChainState) Snapshot() ChainHead {
	c.mu.RLock()
	defer c.mu.RUnlock()
	h := c.h
	h.HeadRoot = append([]byte(nil), c.h.HeadRoot...)
	h.ForkVersion = append([]byte(nil), c.h.ForkVersion...)
	h.GenesisValidatorsRoot = append([]byte(nil), c.h.GenesisValidatorsRoot...)
	return h
}

// Advance 把链状态推进到指定 slot。
func (c *ChainState) Advance(slot, justifiedEpoch, finalizedEpoch uint64, headRoot []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.set(slot, justifiedEpoch, finalizedEpoch, headRoot)
}

// Rollback 把链状态回退到指定 slot。回退只影响后续准入判定，绝不触碰历史记录。
func (c *ChainState) Rollback(slot, justifiedEpoch, finalizedEpoch uint64, headRoot []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if slot > c.h.CurrentSlot {
		panic("domain: Rollback called with a slot ahead of current; use Advance")
	}
	c.set(slot, justifiedEpoch, finalizedEpoch, headRoot)
}

func (c *ChainState) set(slot, justifiedEpoch, finalizedEpoch uint64, headRoot []byte) {
	c.h.CurrentSlot = slot
	c.h.HeadRoot = append(c.h.HeadRoot[:0], headRoot...)
	c.h.JustifiedEpoch = justifiedEpoch
	c.h.FinalizedEpoch = finalizedEpoch
}

// EpochOf 返回 slot 所属 epoch。
func EpochOf(slot uint64) uint64 { return slot / SlotsPerEpoch }

func hashChunks(prefix string, h ChainHead, chunks ...[]byte) []byte {
	w := sha256.New()
	w.Write([]byte(prefix))
	w.Write(h.ForkVersion)
	w.Write(h.GenesisValidatorsRoot)
	for _, c := range chunks {
		w.Write(c)
	}
	return w.Sum(nil)
}

func u64b(v uint64) []byte {
	b := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		b[i] = byte(v)
		v >>= 8
	}
	return b
}
