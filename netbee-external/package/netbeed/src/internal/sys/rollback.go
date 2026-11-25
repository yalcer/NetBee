package sys

import (
	"os"
	"path/filepath"
	"sync"
	"time"
)

type PendingCommit struct {
	Active       bool      `json:"active"`
	Reason       string    `json:"reason,omitempty"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
	RemainingSec int       `json:"remaining_seconds"`
}

type fileSnapshot struct {
	exists bool
	data   []byte
	mode   os.FileMode
}

type RollbackManager struct {
	mu      sync.Mutex
	active  bool
	reason  string
	expires time.Time
	timer   *time.Timer
	backups map[string]fileSnapshot
	onRevs  []func()
}

func NewRollbackManager() *RollbackManager {
	return &RollbackManager{}
}

func snapshotFile(path string) fileSnapshot {
	info, err := os.Stat(path)
	if err != nil {
		return fileSnapshot{exists: false}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fileSnapshot{exists: false}
	}
	return fileSnapshot{exists: true, data: data, mode: info.Mode().Perm()}
}

// Begin snapshots the listed files (including exact permissions) BEFORE they are modified
// and schedules automatic rollback if Confirm() is not called within timeout.
func (rm *RollbackManager) Begin(reason string, timeout time.Duration, files []string, onRevert func()) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if rm.timer != nil {
		rm.timer.Stop()
	}
	if !rm.active {
		rm.backups = make(map[string]fileSnapshot, len(files))
		rm.onRevs = nil
		for _, f := range files {
			rm.backups[f] = snapshotFile(f)
		}
	} else {
		for _, f := range files {
			if _, ok := rm.backups[f]; !ok {
				rm.backups[f] = snapshotFile(f)
			}
		}
	}
	if onRevert != nil {
		rm.onRevs = append(rm.onRevs, onRevert)
	}
	rm.active = true
	rm.reason = reason
	rm.expires = time.Now().Add(timeout)
	rm.timer = time.AfterFunc(timeout, func() {
		rm.RevertNow()
	})
}

func (rm *RollbackManager) Status() PendingCommit {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	if !rm.active {
		return PendingCommit{Active: false}
	}
	rem := int(time.Until(rm.expires).Seconds())
	if rem < 0 {
		rem = 0
	}
	return PendingCommit{
		Active:       true,
		Reason:       rm.reason,
		ExpiresAt:    rm.expires,
		RemainingSec: rem,
	}
}

func (rm *RollbackManager) Confirm() bool {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	if !rm.active {
		return false
	}
	if rm.timer != nil {
		rm.timer.Stop()
		rm.timer = nil
	}
	rm.active = false
	rm.backups = nil
	rm.onRevs = nil
	return true
}

func atomicRestoreFile(path string, data []byte, mode os.FileMode) {
	if mode == 0 {
		mode = 0644
	}
	dir := filepath.Dir(path)
	_ = os.MkdirAll(dir, 0755)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".rb-*")
	if err != nil {
		_ = os.WriteFile(path, data, mode)
		_ = os.Chmod(path, mode)
		return
	}
	tmp := f.Name()
	_ = f.Chmod(mode)
	_, wErr := f.Write(data)
	_ = f.Sync()
	cErr := f.Close()
	if wErr != nil || cErr != nil {
		_ = os.Remove(tmp)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
	}
}

func (rm *RollbackManager) RevertNow() bool {
	rm.mu.Lock()
	if !rm.active {
		rm.mu.Unlock()
		return false
	}
	if rm.timer != nil {
		rm.timer.Stop()
		rm.timer = nil
	}
	backups := rm.backups
	onRevs := rm.onRevs
	rm.active = false
	rm.backups = nil
	rm.onRevs = nil
	rm.mu.Unlock()

	for path, snap := range backups {
		if !snap.exists {
			_ = os.Remove(path)
		} else {
			atomicRestoreFile(path, snap.data, snap.mode)
		}
	}
	// Run revert hooks in reverse order (LIFO)
	for i := len(onRevs) - 1; i >= 0; i-- {
		onRevs[i]()
	}
	return true
}
