package sys

import (
	"os"
	"sync"
	"time"
)

type PendingCommit struct {
	Active       bool      `json:"active"`
	Reason       string    `json:"reason,omitempty"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
	RemainingSec int       `json:"remaining_seconds"`
}

type RollbackManager struct {
	mu      sync.Mutex
	active  bool
	reason  string
	expires time.Time
	timer   *time.Timer
	backups map[string][]byte // path -> original bytes (nil means did not exist)
	onRev   func()
}

func NewRollbackManager() *RollbackManager {
	return &RollbackManager{}
}

// Begin snapshots the listed files and schedules automatic rollback if Confirm() is not called within timeout.
func (rm *RollbackManager) Begin(reason string, timeout time.Duration, files []string, onRevert func()) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if rm.timer != nil {
		rm.timer.Stop()
	}
	// If no previous uncommitted snapshot is active, snapshot current working files
	if !rm.active {
		rm.backups = make(map[string][]byte, len(files))
		for _, f := range files {
			if data, err := os.ReadFile(f); err == nil {
				rm.backups[f] = data
			} else {
				rm.backups[f] = nil
			}
		}
	} else {
		// Merge any additional files not yet snapshotted
		for _, f := range files {
			if _, ok := rm.backups[f]; !ok {
				if data, err := os.ReadFile(f); err == nil {
					rm.backups[f] = data
				} else {
					rm.backups[f] = nil
				}
			}
		}
	}
	rm.active = true
	rm.reason = reason
	rm.expires = time.Now().Add(timeout)
	rm.onRev = onRevert
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
	rm.onRev = nil
	return true
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
	onRev := rm.onRev
	rm.active = false
	rm.backups = nil
	rm.onRev = nil
	rm.mu.Unlock()

	for path, data := range backups {
		if data == nil {
			_ = os.Remove(path)
		} else {
			_ = os.WriteFile(path, data, 0644)
		}
	}
	if onRev != nil {
		onRev()
	}
	return true
}
