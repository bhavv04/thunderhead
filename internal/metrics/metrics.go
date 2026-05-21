package metrics

import "sync/atomic"

// Counters holds atomic request counters for the TUI to read.
// The proxy increments these on every request — no locks needed.
type Counters struct {
	Total   atomic.Int64
	Allowed atomic.Int64
	Tarpit  atomic.Int64
	Blocked atomic.Int64
}

func New() *Counters {
	return &Counters{}
}