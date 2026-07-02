package blocklist

import (
	"net"
	"strings"
	"sync"
)

type Config struct {
	CIDRs []string `json:"cidrs"`
	IPs   []string `json:"ips"`
}

type Blocklist struct {
	mu   sync.RWMutex
	nets []*net.IPNet
	ips  []net.IP
}

func New(cfg Config) *Blocklist {
	b := &Blocklist{}
	for _, entry := range cfg.CIDRs {
		_, ipNet, err := net.ParseCIDR(entry)
		if err == nil {
			b.nets = append(b.nets, ipNet)
		}
	}
	for _, entry := range cfg.IPs {
		ip := net.ParseIP(strings.TrimSpace(entry))
		if ip != nil {
			b.ips = append(b.ips, ip)
		}
	}
	return b
}

func (b *Blocklist) IsBlocked(ip string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()

	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, blocked := range b.ips {
		if blocked.Equal(parsed) {
			return true
		}
	}
	for _, network := range b.nets {
		if network.Contains(parsed) {
			return true
		}
	}
	return false
}

func (b *Blocklist) Add(entry string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if strings.Contains(entry, "/") {
		_, ipNet, err := net.ParseCIDR(entry)
		if err == nil {
			b.nets = append(b.nets, ipNet)
		}
		return
	}
	ip := net.ParseIP(strings.TrimSpace(entry))
	if ip != nil {
		b.ips = append(b.ips, ip)
	}
}

func (b *Blocklist) Remove(entry string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if strings.Contains(entry, "/") {
		_, target, err := net.ParseCIDR(entry)
		if err != nil {
			return
		}
		filtered := b.nets[:0]
		for _, n := range b.nets {
			if n.String() != target.String() {
				filtered = append(filtered, n)
			}
		}
		b.nets = filtered
		return
	}

	target := net.ParseIP(strings.TrimSpace(entry))
	if target == nil {
		return
	}
	filtered := b.ips[:0]
	for _, ip := range b.ips {
		if !ip.Equal(target) {
			filtered = append(filtered, ip)
		}
	}
	b.ips = filtered
}

func (b *Blocklist) Entries() (ips []string, cidrs []string) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	for _, ip := range b.ips {
		ips = append(ips, ip.String())
	}
	for _, n := range b.nets {
		cidrs = append(cidrs, n.String())
	}
	return ips, cidrs
}