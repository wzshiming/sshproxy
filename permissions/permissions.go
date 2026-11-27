package permissions

import (
	"encoding/json"
	"net/netip"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/wzshiming/sshd"
)

type Permissions map[string]Permission

func (p Permissions) Allow(req string, args string) bool {
	permission, ok := p[req]
	if !ok {
		return false
	}
	return permission.Allow(req, args)
}

// Permission decides the arguments allowed for one kind of request.
//
// If Allows is set, only arguments matching one of its entries are allowed.
// Otherwise, if Blocks is set, all arguments but those matching one of its
// entries are allowed. Otherwise Default decides.
//
// An entry matches an argument that is equal to it, or that it matches as a
// pattern in the syntax of path.Match, such as "*.example.com:443" or
// "/run/*.sock". An entry of the form host:port also matches an address
// whose host is equal to, matches the pattern of, or lies in the CIDR prefix
// of its host, and whose port is equal to its port, lies in its range
// "low-high", or is anything for the port "*". Examples: "10.0.0.0/8:*",
// "[fd00::/8]:443" and "*.example.com:8000-8999".
type Permission struct {
	Default bool     `json:"default,omitempty"`
	Allows  []string `json:"allows,omitempty"`
	Blocks  []string `json:"blocks,omitempty"`
}

func (p Permission) Allow(req string, args string) bool {
	if p.Allows != nil {
		for _, item := range p.Allows {
			if match(item, args) {
				return true
			}
		}
		return false
	}
	if p.Blocks != nil {
		for _, item := range p.Blocks {
			if match(item, args) {
				return false
			}
		}
		return true
	}
	return p.Default
}

// match reports whether args is matched by the entry pattern.
func match(pattern, args string) bool {
	if pattern == args || globMatch(pattern, args) {
		return true
	}
	patternHost, patternPort, ok := splitHostPort(pattern)
	if !ok {
		return false
	}
	host, port, ok := splitHostPort(args)
	if !ok {
		return false
	}
	return matchHost(patternHost, host) && matchPort(patternPort, port)
}

func globMatch(pattern, s string) bool {
	ok, err := path.Match(pattern, s)
	return err == nil && ok
}

// splitHostPort splits an address at its last colon and drops the brackets of
// its host. Unlike net.SplitHostPort it accepts the unbracketed IPv6 hosts in
// the addresses of forwarding requests, such as "::1:80".
func splitHostPort(address string) (host, port string, ok bool) {
	i := strings.LastIndexByte(address, ':')
	if i < 0 {
		return "", "", false
	}
	host, port = address[:i], address[i+1:]
	if len(host) >= 2 && host[0] == '[' && host[len(host)-1] == ']' {
		host = host[1 : len(host)-1]
	}
	return host, port, true
}

func matchHost(pattern, host string) bool {
	if pattern == host || globMatch(pattern, host) {
		return true
	}
	prefix, err := netip.ParsePrefix(pattern)
	if err != nil {
		return false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return prefix.Contains(addr.Unmap())
}

func matchPort(pattern, port string) bool {
	if pattern == port || pattern == "*" {
		return true
	}
	low, high, ok := strings.Cut(pattern, "-")
	if !ok {
		return false
	}
	lowPort, err := strconv.ParseUint(low, 10, 16)
	if err != nil {
		return false
	}
	highPort, err := strconv.ParseUint(high, 10, 16)
	if err != nil {
		return false
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return false
	}
	return lowPort <= n && n <= highPort
}

type PermissionsFromFile struct {
	path   string
	period time.Duration

	mut         sync.Mutex
	permissions *Permissions
	latestTime  time.Time
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
	return perm.Allow(req, args)
}

// check returns the permissions of the file, read again once they are older
// than the period. It holds the lock while reading, so that requests arriving
// together wait for one read instead of each reading the file.
func (s *PermissionsFromFile) check() (*Permissions, bool) {
	s.mut.Lock()
	defer s.mut.Unlock()
	if s.permissions == nil || time.Since(s.latestTime) > s.period {
		s.permissions = s.read()
		s.latestTime = time.Now()
	}
	return s.permissions, s.permissions != nil
}

// read returns the permissions in the file, or nil if it cannot be read or parsed.
func (s *PermissionsFromFile) read() *Permissions {
	f, err := os.ReadFile(s.path)
	if err != nil {
		return nil
	}
	var perm *Permissions
	if err := json.Unmarshal(f, &perm); err != nil {
		return nil
	}
	return perm
}
