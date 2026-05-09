package allowlist

import (
	"net"
	"strings"
)

type Config struct {
	IPs        []string `json:"ips"`
	UserAgents []string `json:"user_agents"`
}

type Allowlist struct {
	nets       []*net.IPNet
	ips        []net.IP
	userAgents []string
}

func New(cfg Config) *Allowlist {
	a := &Allowlist{}

	for _, entry := range cfg.IPs {
		if strings.Contains(entry, "/") {
			// CIDR range
			_, ipNet, err := net.ParseCIDR(entry)
			if err == nil {
				a.nets = append(a.nets, ipNet)
			}
		} else {
			// Single IP
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
	parsed := net.ParseIP(ip)

	if parsed != nil {
		// Check single IPs
		for _, allowed := range a.ips {
			if allowed.Equal(parsed) {
				return true
			}
		}
		// Check CIDR ranges
		for _, network := range a.nets {
			if network.Contains(parsed) {
				return true
			}
		}
	}

	// Check user agent substrings
	uaLower := strings.ToLower(userAgent)
	for _, allowed := range a.userAgents {
		if strings.Contains(uaLower, strings.ToLower(allowed)) {
			return true
		}
	}

	return false
}