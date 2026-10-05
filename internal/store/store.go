// Package store 实现防罚没记录的崩溃安全持久化。
//
// 提交协议：所有状态先写入同目录临时文件、fsync 后 rename 到正式文件，
// 再 fsync 父目录。rename 是原子提交点：崩溃后要么看到旧文件，要么看到新文件。
package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/lechandonga/validator-slashing-guard-go/internal/domain"
)

type persistedAtt struct{ domain.AttestationRecord }
type persistedBlock struct{ domain.BlockRecord }

// fileFormat 是磁盘文件格式（版本化，拒绝未知版本与被截断内容）。
type fileFormat struct {
	Version      int              `json:"version"`
	Attestations []persistedAtt   `json:"attestations"`
	Blocks       []persistedBlock `json:"blocks"`
}

const currentVersion = 1

// CrashHook 在原子提交边界被调用，用于测试“任意时点崩溃”。
// 返回 true 表示模拟崩溃（不执行 rename，直接退出当前提交）。
type CrashHook func(phase string) bool

// Store 是内存索引 + 单文件原子持久化。所有变更在同一把锁内完成，
// 因此签名准入、防罚没判定与固化对调用方是一个串行化的临界区。
type Store struct {
	mu     sync.Mutex
	path   string
	atts   []domain.AttestationRecord
	blocks []domain.BlockRecord
	crash  CrashHook
	loaded bool
}

func Open(path string) (*Store, error) {
	s := &Store{path: path}
	if err := s.loadLocked(); err != nil {
		return nil, err
	}
	return s, nil
}

// SetCrashHook 安装崩溃注入钩子（仅测试使用）。
func (s *Store) SetCrashHook(h CrashHook) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.crash = h
}

func (s *Store) loadLocked() error {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		s.atts, s.blocks, s.loaded = nil, nil, true
		return nil
	} else if err != nil {
		return err
	}
	var f fileFormat
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return fmt.Errorf("store: cannot parse %s: %w", s.path, err)
	}
	if dec.More() {
		return fmt.Errorf("store: %s contains trailing data", s.path)
	}
	if f.Version != currentVersion {
		return fmt.Errorf("store: unsupported record version %d", f.Version)
	}
	s.atts = make([]domain.AttestationRecord, 0, len(f.Attestations))
	for _, a := range f.Attestations {
		s.atts = append(s.atts, a.AttestationRecord)
	}
	s.blocks = make([]domain.BlockRecord, 0, len(f.Blocks))
	for _, b := range f.Blocks {
		s.blocks = append(s.blocks, b.BlockRecord)
	}
	s.loaded = true
	return nil
}

// View 在持锁快照上执行只读判定函数。
func (s *Store) View(fn func(atts []domain.AttestationRecord, blocks []domain.BlockRecord)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(append([]domain.AttestationRecord(nil), s.atts...), append([]domain.BlockRecord(nil), s.blocks...))
}

// Update 在同一把锁内完成“读取当前记录 -> 判定 -> 得到新集合 -> 原子固化”。
// fn 返回的集合即新的完整状态；返回错误时不写入任何内容。
func (s *Store) Update(fn func(atts []domain.AttestationRecord, blocks []domain.BlockRecord) (
	[]domain.AttestationRecord, []domain.BlockRecord, error)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	atts := append([]domain.AttestationRecord(nil), s.atts...)
	blocks := append([]domain.BlockRecord(nil), s.blocks...)
	newAtts, newBlocks, err := fn(atts, blocks)
	if err != nil {
		return err
	}
	return s.commitLocked(newAtts, newBlocks)
}

// AddAttestation / AddBlock 的提交语义见 guard 层；这里保证“内存更新与磁盘原子提交要么都发生，要么都不发生”。
func (s *Store) AddAttestation(rec domain.AttestationRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := append(append([]domain.AttestationRecord(nil), s.atts...), rec)
	return s.commitLocked(next, s.blocks)
}

func (s *Store) AddBlock(rec domain.BlockRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := append(append([]domain.BlockRecord(nil), s.blocks...), rec)
	return s.commitLocked(s.atts, next)
}

// Replace 用于导入：用“合并后完整集合”原子替换现有集合。
// 任何此前的解析/冲突错误都在调用前发生，本函数只执行整体写入，杜绝部分写入。
func (s *Store) Replace(atts []domain.AttestationRecord, blocks []domain.BlockRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.commitLocked(
		append([]domain.AttestationRecord(nil), atts...),
		append([]domain.BlockRecord(nil), blocks...),
	)
}

func (s *Store) commitLocked(atts []domain.AttestationRecord, blocks []domain.BlockRecord) error {
	f := fileFormat{Version: currentVersion}
	for _, a := range atts {
		f.Attestations = append(f.Attestations, persistedAtt{a})
	}
	for _, b := range blocks {
		f.Blocks = append(f.Blocks, persistedBlock{b})
	}
	data, err := json.MarshalIndent(&f, "", "  ")
	if err != nil {
		return err
	}

	if s.crash != nil && s.crash("before_rename") {
		return errSimulatedCrash
	}

	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".records-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		os.Remove(tmpName)
		return err
	}
	if df, err := os.Open(dir); err == nil {
		_ = df.Sync()
		_ = df.Close()
	}

	if s.crash != nil && s.crash("after_rename") {
		s.atts, s.blocks = atts, blocks
		return errSimulatedCrash
	}

	s.atts, s.blocks = atts, blocks
	return nil
}

// Snapshot 返回记录的完整拷贝。
func (s *Store) Snapshot() ([]domain.AttestationRecord, []domain.BlockRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]domain.AttestationRecord(nil), s.atts...),
		append([]domain.BlockRecord(nil), s.blocks...)
}

var errSimulatedCrash = errors.New("store: simulated crash before commit completed")

// SimulatedCrash 报告错误是否为测试注入的崩溃。
func SimulatedCrash(err error) bool { return errors.Is(err, errSimulatedCrash) }
