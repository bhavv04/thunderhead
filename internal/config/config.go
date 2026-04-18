package config

import (
	"encoding/json"
	"os"
	"time"
)

type Action string

const (
	ActionLog   Action = "log"
	ActionTarpit Action = "tarpit"
	ActionBlock  Action = "block"
)

type Thresholds struct {
	Tarpit float64 `json:"tarpit"` // score >= this -> tarpit
	Block  float64 `json:"block"`  // score >= this -> block
}

type TarpitConfig struct {
	Delay time.Duration `json:"delay"` // how long to delay tarpitted requests
}

type Config struct {
	ListenAddr  string       `json:"listen_addr"`  // e.g. ":8080"
	UpstreamURL string       `json:"upstream_url"` // e.g. "http://localhost:3000"
	Thresholds  Thresholds   `json:"thresholds"`
	Tarpit      TarpitConfig `json:"tarpit"`
	LogFile     string       `json:"log_file"` // path to log file, "" = stdout
}

func Default() *Config {
	return &Config{
		ListenAddr:  ":8080",
		UpstreamURL: "http://localhost:3000",
		Thresholds: Thresholds{
			Tarpit: 40.0,
			Block:  75.0,
		},
		Tarpit: TarpitConfig{
			Delay: 5 * time.Second,
		},
		LogFile: "",
	}
}

func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	cfg := Default()
	if err := json.NewDecoder(f).Decode(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}