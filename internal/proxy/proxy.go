package proxy

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/bhav/thunderhead/internal/analyzer"
	"github.com/bhav/thunderhead/internal/config"
	"github.com/bhav/thunderhead/internal/logger"
)

type Proxy struct {
	cfg      *config.Config
	analyzer *analyzer.Analyzer
	logger   *logger.Logger
	upstream *httputil.ReverseProxy
}

func New(cfg *config.Config, az *analyzer.Analyzer, log *logger.Logger) (*Proxy, error) {
	target, err := url.Parse(cfg.UpstreamURL)
	if err != nil {
		return nil, err
	}
	return &Proxy{
		cfg:      cfg,
		analyzer: az,
		logger:   log,
		upstream: httputil.NewSingleHostReverseProxy(target),
	}, nil
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/thunderhead/status" {
		p.handleStatus(w, r)
		return
	}

	ip := extractIP(r)
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
	w.Header().Set("Content-Type", "application/json")
	status := p.analyzer.Status()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"clients": status,
	})
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