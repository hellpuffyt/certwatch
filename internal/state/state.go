// Package state persists check results between certwatch runs so it can
// report what's new, what's resolved, and whether a certificate's issuer or
// serial number changed since the last run (an unexpected re-issue).
package state

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"certwatch/internal/certcheck"
)

// Entry is the persisted record for a single host from the previous run.
type Entry struct {
	Host         string             `json:"host"`
	Port         int                `json:"port"`
	Severity     certcheck.Severity `json:"severity"`
	Issuer       string             `json:"issuer,omitempty"`
	SerialNumber string             `json:"serial_number,omitempty"`
	NotAfter     time.Time          `json:"not_after,omitempty"`
	LastChecked  time.Time          `json:"last_checked"`
}

// State is the full persisted document: one Entry per host key.
type State struct {
	Entries map[string]Entry `json:"entries"`
}

// New returns an empty state, safe to diff against (everything will show up
// as new).
func New() *State {
	return &State{Entries: map[string]Entry{}}
}

// Load reads a state file from disk. A missing file is not an error: it
// simply returns an empty state, since the very first run of certwatch
// against a host has nothing to compare against.
func Load(path string) (*State, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return New(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading state %s: %w", path, err)
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parsing state %s: %w", path, err)
	}
	if s.Entries == nil {
		s.Entries = map[string]Entry{}
	}
	return &s, nil
}

// Save writes the state to disk as indented JSON.
func (s *State) Save(path string) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling state: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("writing state %s: %w", path, err)
	}
	return nil
}

// FromResults builds a fresh State snapshot from this run's results, ready
// to be saved for the next run to diff against.
func FromResults(results []certcheck.Result) *State {
	s := New()
	for _, r := range results {
		if r.Severity == certcheck.SeverityError {
			// Don't overwrite last-known-good state with a transient
			// network failure; keep whatever was there (handled by
			// caller merging), and don't record a bogus entry here.
			continue
		}
		s.Entries[r.Key()] = Entry{
			Host:         r.Host,
			Port:         r.Port,
			Severity:     r.Severity,
			Issuer:       r.Issuer,
			SerialNumber: r.SerialNumber,
			NotAfter:     r.NotAfter,
			LastChecked:  r.CheckedAt,
		}
	}
	return s
}

// MergeForward returns a new State suitable for saving after this run: for
// every current result it records fresh state, and for hosts that errored
// this run (and so have no fresh data) it carries forward their previous
// entry unchanged, so a transient network blip doesn't erase history.
func MergeForward(previous *State, results []certcheck.Result) *State {
	next := FromResults(results)
	if previous == nil {
		return next
	}
	for _, r := range results {
		if r.Severity != certcheck.SeverityError {
			continue
		}
		if prev, ok := previous.Entries[r.Key()]; ok {
			next.Entries[r.Key()] = prev
		}
	}
	return next
}

// Diff describes what changed for one host between the previous state and
// this run's result.
type Diff struct {
	Key           string
	Result        certcheck.Result
	New           bool // wasn't a problem before (or unseen), is one now
	Resolved      bool // was a problem before, is not one now
	CAChanged     bool // issuer differs from last run
	SerialChanged bool // serial number differs from last run (re-issue)
	FirstSeen     bool // host was not present in previous state at all
}

// Changed reports whether anything about this host is noteworthy: a new
// problem, a resolution, or a CA/serial change. Used to implement
// --only-changed.
func (d Diff) Changed() bool {
	return d.New || d.Resolved || d.CAChanged || d.SerialChanged
}

// Compare diffs this run's results against the previous state.
func Compare(previous *State, results []certcheck.Result) []Diff {
	diffs := make([]Diff, 0, len(results))
	for _, r := range results {
		d := Diff{Key: r.Key(), Result: r}
		prev, ok := previous.Entries[r.Key()]
		if !ok {
			d.FirstSeen = true
			if r.Problem() {
				d.New = true
			}
			diffs = append(diffs, d)
			continue
		}
		wasProblem := prev.Severity != certcheck.SeverityOK
		isProblem := r.Problem()
		if !wasProblem && isProblem {
			d.New = true
		}
		if wasProblem && !isProblem {
			d.Resolved = true
		}
		if r.Severity != certcheck.SeverityError {
			if prev.Issuer != "" && r.Issuer != "" && prev.Issuer != r.Issuer {
				d.CAChanged = true
			}
			if prev.SerialNumber != "" && r.SerialNumber != "" && prev.SerialNumber != r.SerialNumber {
				d.SerialChanged = true
			}
		}
		diffs = append(diffs, d)
	}
	return diffs
}
