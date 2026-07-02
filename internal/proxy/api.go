package proxy

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// ─── Auth middleware ──────────────────────────────────────────────────────────

func (p *Proxy) apiAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if p.cfg.APIKey == "" {
			// no key configured — deny all API access
			apiError(w, "API key not configured", http.StatusServiceUnavailable)
			return
		}
		key := r.Header.Get("X-API-Key")
		if key != p.cfg.APIKey {
			apiError(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// ─── Router ───────────────────────────────────────────────────────────────────

func (p *Proxy) apiMux() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/v1/health",     p.apiAuth(p.handleHealth))
	mux.HandleFunc("GET /api/v1/clients",    p.apiAuth(p.handleClients))
	mux.HandleFunc("GET /api/v1/metrics",    p.apiAuth(p.handleMetrics))
	mux.HandleFunc("GET /api/v1/config",     p.apiAuth(p.handleConfig))
	mux.HandleFunc("GET /api/v1/blocklist",  p.apiAuth(p.handleBlocklistGet))
	mux.HandleFunc("POST /api/v1/blocklist", p.apiAuth(p.handleBlocklistAdd))
	mux.HandleFunc("DELETE /api/v1/blocklist", p.apiAuth(p.handleBlocklistRemove))
	mux.HandleFunc("GET /api/v1/allowlist",  p.apiAuth(p.handleAllowlistGet))
	mux.HandleFunc("POST /api/v1/allowlist", p.apiAuth(p.handleAllowlistAdd))
	mux.HandleFunc("DELETE /api/v1/allowlist", p.apiAuth(p.handleAllowlistRemove))

	return mux
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

func (p *Proxy) handleHealth(w http.ResponseWriter, r *http.Request) {
	apiJSON(w, map[string]any{
		"status":  "ok",
		"uptime":  time.Since(p.startTime).Truncate(time.Second).String(),
		"version": "v0.2.0",
	})
}

func (p *Proxy) handleClients(w http.ResponseWriter, r *http.Request) {
	apiJSON(w, map[string]any{
		"clients": p.analyzer.Status(),
	})
}

func (p *Proxy) handleMetrics(w http.ResponseWriter, r *http.Request) {
	var total, allowed, tarpit, blocked int64
	if p.metrics != nil {
		total   = p.metrics.Total.Load()
		allowed = p.metrics.Allowed.Load()
		tarpit  = p.metrics.Tarpit.Load()
		blocked = p.metrics.Blocked.Load()
	}
	apiJSON(w, map[string]any{
		"total":   total,
		"allowed": allowed,
		"tarpit":  tarpit,
		"blocked": blocked,
		"uptime":  time.Since(p.startTime).Truncate(time.Second).String(),
	})
}

func (p *Proxy) handleConfig(w http.ResponseWriter, r *http.Request) {
	apiJSON(w, map[string]any{
		"listen_addr":  p.cfg.ListenAddr,
		"upstream_url": p.cfg.UpstreamURL,
		"thresholds":   p.cfg.Thresholds,
		"tarpit_delay": p.cfg.Tarpit.Delay.String(),
		"expiry_days":  p.cfg.ExpiryDays,
		"dry_run":      p.dryRun,
	})
}

// ── Blocklist ─────────────────────────────────────────────────────────────────

func (p *Proxy) handleBlocklistGet(w http.ResponseWriter, r *http.Request) {
	ips, cidrs := p.blocklist.Entries()
	apiJSON(w, map[string]any{
		"ips":   orEmpty(ips),
		"cidrs": orEmpty(cidrs),
	})
}

func (p *Proxy) handleBlocklistAdd(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Entry string `json:"entry"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Entry) == "" {
		apiError(w, "invalid request body — expected {\"entry\": \"<ip or cidr>\"}", http.StatusBadRequest)
		return
	}
	p.blocklist.Add(strings.TrimSpace(body.Entry))
	apiJSON(w, map[string]any{"ok": true, "entry": body.Entry})
}

func (p *Proxy) handleBlocklistRemove(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Entry string `json:"entry"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Entry) == "" {
		apiError(w, "invalid request body — expected {\"entry\": \"<ip or cidr>\"}", http.StatusBadRequest)
		return
	}
	p.blocklist.Remove(strings.TrimSpace(body.Entry))
	apiJSON(w, map[string]any{"ok": true, "entry": body.Entry})
}

// ── Allowlist ─────────────────────────────────────────────────────────────────

func (p *Proxy) handleAllowlistGet(w http.ResponseWriter, r *http.Request) {
	ips, nets, uas := p.allowlist.Entries()
	apiJSON(w, map[string]any{
		"ips":         orEmpty(ips),
		"cidrs":       orEmpty(nets),
		"user_agents": orEmpty(uas),
	})
}

func (p *Proxy) handleAllowlistAdd(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Entry string `json:"entry"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Entry) == "" {
		apiError(w, "invalid request body — expected {\"entry\": \"<ip, cidr, or ua>\"}", http.StatusBadRequest)
		return
	}
	p.allowlist.Add(strings.TrimSpace(body.Entry))
	apiJSON(w, map[string]any{"ok": true, "entry": body.Entry})
}

func (p *Proxy) handleAllowlistRemove(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Entry string `json:"entry"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Entry) == "" {
		apiError(w, "invalid request body — expected {\"entry\": \"<ip, cidr, or ua>\"}", http.StatusBadRequest)
		return
	}
	p.allowlist.Remove(strings.TrimSpace(body.Entry))
	apiJSON(w, map[string]any{"ok": true, "entry": body.Entry})
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func apiJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(v)
}

func apiError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func orEmpty[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}