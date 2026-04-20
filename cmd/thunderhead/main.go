package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/bhav/thunderhead/internal/analyzer"
	"github.com/bhav/thunderhead/internal/config"
	"github.com/bhav/thunderhead/internal/logger"
	"github.com/bhav/thunderhead/internal/proxy"
)

func main() {
	cfgPath := flag.String("config", "", "path to config file (optional)")
	flag.Parse()

	var cfg *config.Config
	if *cfgPath != "" {
		var err error
		cfg, err = config.Load(*cfgPath)
		if err != nil {
			log.Fatalf("failed to load config: %v", err)
		}
	} else {
		cfg = config.Default()
	}

	log.Printf("thunderhead starting on %s -> %s", cfg.ListenAddr, cfg.UpstreamURL)
	log.Printf("thresholds: tarpit=%.0f block=%.0f", cfg.Thresholds.Tarpit, cfg.Thresholds.Block)

	//parse robots.txt from upstream and pass disallowed paths
	disallowed := analyzer.FetchDisallowedPaths(cfg.UpstreamURL)
	az := analyzer.New(disallowed)

	lg, err := logger.New(cfg.LogFile)
	if err != nil {
		log.Fatalf("failed to init logger: %v", err)
	}

	p, err := proxy.New(cfg, az, lg)
	if err != nil {
		log.Fatalf("failed to init proxy: %v", err)
	}

	if err := http.ListenAndServe(cfg.ListenAddr, p); err != nil {
		log.Fatalf("server error: %v", err)
	}
}