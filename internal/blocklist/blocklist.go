package blocklist

import (
	"net"
	"strings"
)

type Config struct {
	CIDRs []string `json:"cidrs"`
	IPs   []string `json:"ips"`
}

type Blocklist struct {
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
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}

	for _, allowed := range b.ips {
		if allowed.Equal(parsed) {
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