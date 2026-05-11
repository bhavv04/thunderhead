package store

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

type ClientRecord struct {
	LastScore      float64   `json:"last_score"`
	RobotsViolated bool      `json:"robots_violated"`
	LastSeen       time.Time `json:"last_seen"`
}

type State struct {
	Clients map[string]ClientRecord `json:"clients"`
}

type Store struct {
	mu   sync.Mutex
	path string
}

func New(path string) *Store {
	return &Store{path: path}
}

func (s *Store) Load() (*State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	f, err := os.Open(s.path)
	if os.IsNotExist(err) {
		// No state file yet, return empty state
		return &State{Clients: make(map[string]ClientRecord)}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var state State
	if err := json.NewDecoder(f).Decode(&state); err != nil {
		return nil, err
	}
	if state.Clients == nil {
		state.Clients = make(map[string]ClientRecord)
	}
	return &state, nil
}

func (s *Store) Save(state *State) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	f, err := os.CreateTemp("", "thunderhead-state-*.json")
	if err != nil {
		return err
	}
	tmpPath := f.Name()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(state); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return err
	}
	f.Close()

	return os.Rename(tmpPath, s.path)
}