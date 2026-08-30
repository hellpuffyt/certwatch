// Package inventory loads and validates the host inventory that certwatch
// monitors. An inventory lists the hosts to check along with optional
// per-host overrides (port, SNI, owner/team tags, and lead-time tiers).
package inventory

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// LeadTimes defines the day thresholds used to classify a certificate's
// remaining validity into a severity tier. A certificate is:
//
//	expired        if it is already past NotAfter
//	not-yet-valid  if NotBefore is in the future
//	critical       if days remaining < CriticalDays
//	warning        if days remaining < WarningDays
//	notice         if days remaining < NoticeDays
//	ok             otherwise
type LeadTimes struct {
	CriticalDays int `yaml:"critical_days,omitempty" json:"critical_days,omitempty"`
	WarningDays  int `yaml:"warning_days,omitempty" json:"warning_days,omitempty"`
	NoticeDays   int `yaml:"notice_days,omitempty" json:"notice_days,omitempty"`
}

// DefaultLeadTimes returns the built-in sane defaults: critical < 7 days,
// warning < 30 days, notice < 60 days.
func DefaultLeadTimes() LeadTimes {
	return LeadTimes{CriticalDays: 7, WarningDays: 30, NoticeDays: 60}
}

// IsZero reports whether no thresholds were set (i.e. inherit from parent).
func (l LeadTimes) IsZero() bool {
	return l.CriticalDays == 0 && l.WarningDays == 0 && l.NoticeDays == 0
}

// Merge returns a copy of l with any zero fields filled in from the given
// fallback. Used to apply per-host overrides on top of inventory defaults.
func (l LeadTimes) Merge(fallback LeadTimes) LeadTimes {
	out := l
	if out.CriticalDays == 0 {
		out.CriticalDays = fallback.CriticalDays
	}
	if out.WarningDays == 0 {
		out.WarningDays = fallback.WarningDays
	}
	if out.NoticeDays == 0 {
		out.NoticeDays = fallback.NoticeDays
	}
	return out
}

// Host describes a single monitored endpoint.
type Host struct {
	Name      string     `yaml:"name" json:"name"`
	Port      int        `yaml:"port,omitempty" json:"port,omitempty"`
	SNI       string     `yaml:"sni,omitempty" json:"sni,omitempty"`
	Owner     string     `yaml:"owner,omitempty" json:"owner,omitempty"`
	Team      string     `yaml:"team,omitempty" json:"team,omitempty"`
	LeadTimes *LeadTimes `yaml:"lead_times,omitempty" json:"lead_times,omitempty"`
}

// EffectivePort returns the configured port, defaulting to 443.
func (h Host) EffectivePort() int {
	if h.Port == 0 {
		return 443
	}
	return h.Port
}

// EffectiveSNI returns the SNI override, defaulting to the host name.
func (h Host) EffectiveSNI() string {
	if h.SNI != "" {
		return h.SNI
	}
	return h.Name
}

// Key returns a stable identifier for this host used for state tracking,
// combining the dial target and port (SNI does not participate, since the
// same physical endpoint may be probed under different names).
func (h Host) Key() string {
	return fmt.Sprintf("%s:%d", h.Name, h.EffectivePort())
}

// EffectiveLeadTimes resolves this host's lead times against the inventory
// defaults, falling back to DefaultLeadTimes() for anything left unset.
func (h Host) EffectiveLeadTimes(defaults LeadTimes) LeadTimes {
	merged := defaults.Merge(DefaultLeadTimes())
	if h.LeadTimes == nil {
		return merged
	}
	return h.LeadTimes.Merge(merged)
}

// Inventory is the top-level document: a list of hosts plus optional
// defaults applied to every host that doesn't override them.
type Inventory struct {
	Defaults LeadTimes `yaml:"defaults,omitempty" json:"defaults,omitempty"`
	Hosts    []Host    `yaml:"hosts" json:"hosts"`
}

// Validate checks the inventory for structural problems: no hosts, empty
// names, or negative/duplicate ports on the same host name.
func (inv Inventory) Validate() error {
	if len(inv.Hosts) == 0 {
		return fmt.Errorf("inventory has no hosts")
	}
	seen := make(map[string]bool)
	for i, h := range inv.Hosts {
		if strings.TrimSpace(h.Name) == "" {
			return fmt.Errorf("host[%d]: name is required", i)
		}
		if h.Port < 0 || h.Port > 65535 {
			return fmt.Errorf("host %q: invalid port %d", h.Name, h.Port)
		}
		key := h.Key()
		if seen[key] {
			return fmt.Errorf("host %q: duplicate entry for %s", h.Name, key)
		}
		seen[key] = true
	}
	return nil
}

// Load reads an inventory document from disk. YAML is used unless the file
// extension is .json, in which case strict JSON decoding is used.
func Load(path string) (*Inventory, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading inventory %s: %w", path, err)
	}
	return Parse(data, path)
}

// Parse decodes inventory document bytes. The hint (typically a file path)
// is used only to pick JSON vs YAML decoding by extension; pass "" or a
// non-.json name to force YAML (which is a JSON superset for our purposes).
func Parse(data []byte, hint string) (*Inventory, error) {
	var inv Inventory
	var err error
	if strings.EqualFold(filepath.Ext(hint), ".json") {
		dec := json.NewDecoder(strings.NewReader(string(data)))
		dec.DisallowUnknownFields()
		err = dec.Decode(&inv)
	} else {
		err = yaml.Unmarshal(data, &inv)
	}
	if err != nil {
		return nil, fmt.Errorf("parsing inventory: %w", err)
	}
	if err := inv.Validate(); err != nil {
		return nil, err
	}
	return &inv, nil
}
