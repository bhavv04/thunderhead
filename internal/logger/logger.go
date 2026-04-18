package logger

import (
	"encoding/json"
	"io"
	"os"
	"time"
)

type Entry struct {
	Time      time.Time `json:"time"`
	IP        string    `json:"ip"`
	Method    string    `json:"method"`
	Path      string    `json:"path"`
	Score     float64   `json:"score"`
	Action    string    `json:"action"`
	UserAgent string    `json:"user_agent"`
}

type Logger struct {
	enc *json.Encoder
}

func New(path string) (*Logger, error) {
	var w io.Writer = os.Stdout
	if path != "" {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return nil, err
		}
		w = f
	}
	return &Logger{enc: json.NewEncoder(w)}, nil
}

func (l *Logger) Log(e Entry) {
	e.Time = time.Now()
	_ = l.enc.Encode(e)
}