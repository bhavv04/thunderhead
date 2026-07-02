package allowlist

import (
	"net"
	"strings"
	"sync"
)

type Config struct {
	IPs        []string `json:"ips"`
	UserAgents []string `json:"user_agents"`
}

type Allowlist struct {
	mu         sync.RWMutex
	nets       []*net.IPNet
	ips        []net.IP
	userAgents []string
}

func New(cfg Config) *Allowlist {
	a := &Allowlist{}
	for _, entry := range cfg.IPs {
		if strings.Contains(entry, "/") {
			_, ipNet, err := net.ParseCIDR(entry)
			if err == nil {
				a.nets = append(a.nets, ipNet)
			}
		} else {
			ip := net.ParseIP(entry)
			if ip != nil {
				a.ips = append(a.ips, ip)
			}
		}
	}
	a.userAgents = cfg.UserAgents
	return a
}

func (a *Allowlist) IsAllowed(ip, userAgent string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()

	parsed := net.ParseIP(ip)
	if parsed != nil {
		for _, allowed := range a.ips {
			if allowed.Equal(parsed) {
				return true
			}
		}
		for _, network := range a.nets {
			if network.Contains(parsed) {
				return true
			}
		}
	}

	uaLower := strings.ToLower(userAgent)
	for _, allowed := range a.userAgents {
		if strings.Contains(uaLower, strings.ToLower(allowed)) {
			return true
		}
	}
	return false
}

func (a *Allowlist) Add(entry string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if strings.Contains(entry, "/") {
		_, ipNet, err := net.ParseCIDR(entry)
		if err == nil {
			a.nets = append(a.nets, ipNet)
		}
		return
	}
	ip := net.ParseIP(entry)
	if ip != nil {
		a.ips = append(a.ips, ip)
	}
}

func (a *Allowlist) Remove(entry string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if strings.Contains(entry, "/") {
		_, target, err := net.ParseCIDR(entry)
		if err != nil {
			return
		}
		filtered := a.nets[:0]
		for _, n := range a.nets {
			if n.String() != target.String() {
				filtered = append(filtered, n)
			}
		}
		a.nets = filtered
		return
	}

	target := net.ParseIP(entry)
	if target == nil {
		return
	}
	filtered := a.ips[:0]
	for _, ip := range a.ips {
		if !ip.Equal(target) {
			filtered = append(filtered, ip)
		}
	}
	a.ips = filtered
}

func (a *Allowlist) Entries() (ips []string, nets []string, uas []string) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	for _, ip := range a.ips {
		ips = append(ips, ip.String())
	}
	for _, n := range a.nets {
		nets = append(nets, n.String())
	}
	return ips, nets, a.userAgents
}