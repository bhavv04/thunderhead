package proxy

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/bhavv04/thunderhead/internal/allowlist"
	"github.com/bhavv04/thunderhead/internal/analyzer"
	"github.com/bhavv04/thunderhead/internal/blocklist"
	"github.com/bhavv04/thunderhead/internal/config"
	"github.com/bhavv04/thunderhead/internal/logger"
)

type Proxy struct {
	cfg       *config.Config
	analyzer  *analyzer.Analyzer
	logger    *logger.Logger
	upstream  *httputil.ReverseProxy
	allowlist *allowlist.Allowlist
	blocklist *blocklist.Blocklist
}

func New(cfg *config.Config, az *analyzer.Analyzer, log *logger.Logger, al *allowlist.Allowlist, bl *blocklist.Blocklist) (*Proxy, error) {
	target, err := url.Parse(cfg.UpstreamURL)
	if err != nil {
		return nil, err
	}
	return &Proxy{
		cfg:       cfg,
		analyzer:  az,
		logger:    log,
		upstream:  httputil.NewSingleHostReverseProxy(target),
		allowlist: al,
		blocklist: bl,
	}, nil
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/thunderhead/status" {
		p.handleStatus(w, r)
		return
	}

	ip := extractIP(r)
	if p.allowlist.IsAllowed(ip, r.Header.Get("User-Agent")) {
		p.upstream.ServeHTTP(w, r)
		return
	}

	if p.blocklist.IsBlocked(ip) {
		p.logger.Log(logger.Entry{
			IP:        ip,
			Method:    r.Method,
			Path:      r.URL.Path,
			Score:     100,
			Action:    "blocklist",
			UserAgent: r.Header.Get("User-Agent"),
		})
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	score := p.analyzer.Score(r, ip)

	action := "allow"
	switch {
	case score >= p.cfg.Thresholds.Block:
		action = "block"
	case score >= p.cfg.Thresholds.Tarpit:
		action = "tarpit"
	}

	p.logger.Log(logger.Entry{
		IP:        ip,
		Method:    r.Method,
		Path:      r.URL.Path,
		Score:     score,
		Action:    action,
		UserAgent: r.Header.Get("User-Agent"),
	})

	switch action {
	case "block":
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	case "tarpit":
		time.Sleep(p.cfg.Tarpit.Delay)
	}

	p.upstream.ServeHTTP(w, r)
}

func (p *Proxy) handleStatus(w http.ResponseWriter, r *http.Request) {
	status := p.analyzer.Status()

	// Serve JSON if requested via API
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"clients": status,
		})
		return
	}

	// Otherwise serve the HTML dashboard
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(renderDashboard(status, p.cfg)))
}

func renderDashboard(status map[string]analyzer.ClientStatus, cfg *config.Config) string {
	rows := ""
	for ip, client := range status {
		action := "allow"
		actionClass := "allow"
		if client.Score >= cfg.Thresholds.Block {
			action = "block"
			actionClass = "block"
		} else if client.Score >= cfg.Thresholds.Tarpit {
			action = "tarpit"
			actionClass = "tarpit"
		}

		robotsStr := "no"
		if client.RobotsViolated {
			robotsStr = "yes"
		}

		rows += fmt.Sprintf(`
		<tr class="%s">
			<td>%s</td>
			<td>%.1f</td>
			<td>%d</td>
			<td>%s</td>
			<td><span class="badge %s">%s</span></td>
		</tr>`, actionClass, ip, client.Score, client.RequestCount, robotsStr, actionClass, action)
	}

	if rows == "" {
		rows = `<tr><td colspan="5" class="empty">No clients tracked yet</td></tr>`
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta http-equiv="refresh" content="5">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Thunderhead</title>
	<style>
		body {
			font-family: monospace;
			padding: 2rem;
		}
		table {
			border-collapse: collapse;
		}
		th, td {
			border: 1px solid #000;
			padding: 0.5rem 1rem;
			text-align: left;
		}
		th {
			background: #f0f0f0;
		}
	</style>
</head>
<body>
	<header>
		<div>
			<h1>Thunderhead</h1>
			<p>Passive intent-scoring reverse proxy · refreshes every 5s</p>
		</div>
		<span class="tag">%s → %s</span>
	</header>
	<div class="stats">
		<div class="stat-card">
			<div class="label">Clients Tracked</div>
			<div class="value">%d</div>
		</div>
		<div class="stat-card">
			<div class="label">Tarpit Threshold</div>
			<div class="value">%.0f</div>
		</div>
		<div class="stat-card">
			<div class="label">Block Threshold</div>
			<div class="value">%.0f</div>
		</div>
	</div>
	<table>
		<thead>
			<tr>
				<th>IP Address</th>
				<th>Score</th>
				<th>Requests</th>
				<th>Robots Violated</th>
				<th>Action</th>
			</tr>
		</thead>
		<tbody>
			%s
		</tbody>
	</table>
	<footer>thunderhead · upstream %s</footer>
</body>
</html>`,
		cfg.ListenAddr, cfg.UpstreamURL,
		len(status),
		cfg.Thresholds.Tarpit,
		cfg.Thresholds.Block,
		rows,
		cfg.UpstreamURL,
	)
}

func extractIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}