package permissions

import (
	"encoding/json"
	"github.com/wzshiming/sshd"
	"os"
	"sync"
	"time"
)

type Permissions map[string]Permission

func (p Permissions) Allow(req string, args string) bool {
	permission, ok := p[req]
	if !ok {
		return false
	}
	return permission.Allow(req, args)
}

type Permission struct {
	Default bool     `json:"default,omitempty"`
	Allows  []string `json:"allows,omitempty"`
	Blocks  []string `json:"blocks,omitempty"`
}

func (p Permission) Allow(req string, args string) bool {
	if p.Allows != nil {
		for _, item := range p.Allows {
			if item == args {
				return true
			}
		}
		return false
	}
	if p.Blocks != nil {
		for _, item := range p.Blocks {
			if item == args {
				return false
			}
		}
		return true
	}
	return p.Default
}

type PermissionsFromFile struct {
	permissions *Permissions
	path        string
	period      time.Duration
	latestTime  time.Time
	mut         sync.RWMutex
}

func NewPermissionsFromFile(file string, period time.Duration) sshd.Permissions {
	if period < time.Second {
		period = time.Second
	}
	return &PermissionsFromFile{
		path:   file,
		period: period,
	}
}

func (s *PermissionsFromFile) Allow(req string, args string) bool {
	perm, ok := s.check()
	if !ok {
		return false
	}
	ok = perm.Allow(req, args)
	return ok
}

func (s *PermissionsFromFile) get() (*Permissions, time.Time) {
	s.mut.RLock()
	defer s.mut.RUnlock()
	return s.permissions, s.latestTime
}

func (s *PermissionsFromFile) check() (*Permissions, bool) {
	perm, latest := s.get()
	if perm == nil || time.Since(latest) > s.period {
		if !s.update() {
			return nil, false
		}
		perm, latest = s.get()
		if perm == nil || time.Since(latest) > s.period {
			return nil, false
		}
	}
	return perm, true
}

func (s *PermissionsFromFile) update() bool {
	var perm *Permissions
	f, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return false
		}
	} else {
		err = json.Unmarshal(f, &perm)
		if err != nil {
			perm = nil
		}
	}
	s.mut.Lock()
	defer s.mut.Unlock()
	s.permissions = perm
	s.latestTime = time.Now()
	return true
}
