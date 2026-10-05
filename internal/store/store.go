// Package store 实现防罚没记录的持久化：
//   - 跨进程互斥文件锁（flock），保证同一时刻只有一个客户端实例可写；
//   - 单次写入采用“临时文件 + fsync + 原子 rename”，杜绝半截记录；
//   - 记录只追加、不修改、不删除；导入以整体替换的方式原子提交。
package store

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/lechandonga/validator-slashing-guard-go/internal/types"
)

const (
	dbFileName = "slashing-protection.json"
	lockName   = "slashing-protection.lock"
	dbVersion  = 1
)

// DB 是记录文件的完整内容。
type DB struct {
	Version               int                       `json:"version"`
	Validator             string                    `json:"validator_pubkey"`
	GenesisValidatorsRoot string                    `json:"genesis_validators_root"`
	Attestations          []types.SignedAttestation `json:"signed_attestations"`
	Proposals             []types.SignedProposal    `json:"signed_blocks"`
}

// Store 管理带锁的防罚没记录数据库。
type Store struct {
	dir       string
	validator types.ValidatorID
	gvr       types.Root

	mu sync.Mutex // 进程内并发串行化；flock 负责跨进程串行化。
	db *DB
	f  *os.File

	// CrashHook 在“记录已 fsync 固化、但签名尚未返回调用方”的窗口被调用。
	// 测试通过让它终止进程（或返回错误）模拟任意时点崩溃。
	CrashHook func(kind types.DutyKind, slot uint64)
}

// Open 打开（必要时创建）记录库，并立即获取独占文件锁。
func Open(dir string, validator types.ValidatorID, gvr types.Root) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	lockPath := filepath.Join(dir, lockName)
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("another signer instance is active (lock %s): %w", lockPath, err)
	}

	st := &Store{dir: dir, validator: validator, gvr: gvr, f: f}
	if err := st.load(); err != nil {
		syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
		return nil, err
	}
	return st, nil
}

// Close 释放锁。
func (s *Store) Close() error {
	if s.f == nil {
		return nil
	}
	err1 := syscall.Flock(int(s.f.Fd()), syscall.LOCK_UN)
	err2 := s.f.Close()
	s.f = nil
	return errors.Join(err1, err2)
}

func (s *Store) dbPath() string { return filepath.Join(s.dir, dbFileName) }

func (s *Store) load() error {
	data, err := os.ReadFile(s.dbPath())
	if errors.Is(err, os.ErrNotExist) {
		s.db = &DB{
			Version:               dbVersion,
			Validator:             "0x" + hex.EncodeToString(s.validator[:]),
			GenesisValidatorsRoot: "0x" + hex.EncodeToString(s.gvr[:]),
		}
		return s.writeDB(s.db)
	}
	if err != nil {
		return err
	}
	var db DB
	if err := json.Unmarshal(data, &db); err != nil {
		// 任何截断/损坏都采取 fail-closed：拒绝启动，绝不猜测放行。
		return fmt.Errorf("slashing protection database is truncated or corrupt: %w", err)
	}
	if db.Version != dbVersion {
		return fmt.Errorf("unsupported slashing protection db version %d", db.Version)
	}
	if db.Validator != "0x"+hex.EncodeToString(s.validator[:]) {
		return fmt.Errorf("db validator identity %q does not match local signer", db.Validator)
	}
	if db.GenesisValidatorsRoot != "0x"+hex.EncodeToString(s.gvr[:]) {
		return fmt.Errorf("db genesis validators root does not match local chain state")
	}
	s.db = &db
	return nil
}

// Attestations / Proposals 返回当前记录的副本。
func (s *Store) Attestations() []types.SignedAttestation {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]types.SignedAttestation, len(s.db.Attestations))
	copy(out, s.db.Attestations)
	return out
}

func (s *Store) Proposals() []types.SignedProposal {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]types.SignedProposal, len(s.db.Proposals))
	copy(out, s.db.Proposals)
	return out
}

// AppendAttestation 固化一条证明记录。该方法在签名结果离开进程前完成 fsync。
func (s *Store) AppendAttestation(rec types.SignedAttestation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	db := s.shallowCopyDB()
	db.Attestations = append(db.Attestations, rec)
	if err := s.writeDB(db); err != nil {
		return err
	}
	s.db = db
	if s.CrashHook != nil {
		s.CrashHook(types.DutyAttestation, rec.Slot)
	}
	return nil
}

// AppendProposal 固化一条区块提议记录。
func (s *Store) AppendProposal(rec types.SignedProposal) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	db := s.shallowCopyDB()
	db.Proposals = append(db.Proposals, rec)
	if err := s.writeDB(db); err != nil {
		return err
	}
	s.db = db
	if s.CrashHook != nil {
		s.CrashHook(types.DutyProposal, rec.Slot)
	}
	return nil
}

// CommitReplacement 原子提交导入合并后的完整记录集。
// 仅在 interchange 全部条目通过校验与合并后调用，因此不存在部分写入。
func (s *Store) CommitReplacement(attestations []types.SignedAttestation, proposals []types.SignedProposal) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	db := s.shallowCopyDB()
	db.Attestations = attestations
	db.Proposals = proposals
	if err := s.writeDB(db); err != nil {
		return err
	}
	s.db = db
	return nil
}

func (s *Store) shallowCopyDB() *DB {
	return &DB{
		Version:               s.db.Version,
		Validator:             s.db.Validator,
		GenesisValidatorsRoot: s.db.GenesisValidatorsRoot,
		Attestations:          append([]types.SignedAttestation(nil), s.db.Attestations...),
		Proposals:             append([]types.SignedProposal(nil), s.db.Proposals...),
	}
}

// writeDB 以 temp+fsync+rename 原子写入，崩溃只可能留下旧版本或新版本，绝不会留下截断文件。
func (s *Store) writeDB(db *DB) error {
	data, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		return err
	}
	path := s.dbPath()
	tmp, err := os.CreateTemp(s.dir, ".db-tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			os.Remove(tmpName)
		}
	}()
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
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	cleanup = false
	// fsync 目录，保证 rename 本身持久化。
	if dir, err := os.Open(s.dir); err == nil {
		_ = dir.Sync()
		dir.Close()
	}
	return nil
}
