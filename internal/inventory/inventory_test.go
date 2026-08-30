package inventory

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultLeadTimes(t *testing.T) {
	d := DefaultLeadTimes()
	if d.CriticalDays != 7 || d.WarningDays != 30 || d.NoticeDays != 60 {
		t.Fatalf("unexpected defaults: %+v", d)
	}
}

func TestLeadTimesMerge(t *testing.T) {
	override := LeadTimes{CriticalDays: 3}
	merged := override.Merge(DefaultLeadTimes())
	if merged.CriticalDays != 3 {
		t.Fatalf("expected override to win, got %d", merged.CriticalDays)
	}
	if merged.WarningDays != 30 || merged.NoticeDays != 60 {
		t.Fatalf("expected fallback fields to fill in, got %+v", merged)
	}
}

func TestHostEffectivePortAndSNI(t *testing.T) {
	h := Host{Name: "example.com"}
	if h.EffectivePort() != 443 {
		t.Fatalf("expected default port 443, got %d", h.EffectivePort())
	}
	if h.EffectiveSNI() != "example.com" {
		t.Fatalf("expected SNI to default to name, got %s", h.EffectiveSNI())
	}

	h2 := Host{Name: "example.com", Port: 8443, SNI: "internal.example.com"}
	if h2.EffectivePort() != 8443 {
		t.Fatalf("expected port 8443, got %d", h2.EffectivePort())
	}
	if h2.EffectiveSNI() != "internal.example.com" {
		t.Fatalf("expected sni override, got %s", h2.EffectiveSNI())
	}
}

func TestHostKey(t *testing.T) {
	h := Host{Name: "example.com", Port: 8443}
	if h.Key() != "example.com:8443" {
		t.Fatalf("unexpected key: %s", h.Key())
	}
	h2 := Host{Name: "example.com"}
	if h2.Key() != "example.com:443" {
		t.Fatalf("unexpected default key: %s", h2.Key())
	}
}

func TestHostEffectiveLeadTimesOverride(t *testing.T) {
	defaults := LeadTimes{CriticalDays: 10, WarningDays: 40, NoticeDays: 90}
	h := Host{Name: "a", LeadTimes: &LeadTimes{CriticalDays: 1}}
	lt := h.EffectiveLeadTimes(defaults)
	if lt.CriticalDays != 1 {
		t.Fatalf("expected host override 1, got %d", lt.CriticalDays)
	}
	if lt.WarningDays != 40 || lt.NoticeDays != 90 {
		t.Fatalf("expected inherited fields, got %+v", lt)
	}
}

func TestHostEffectiveLeadTimesNoOverride(t *testing.T) {
	defaults := LeadTimes{CriticalDays: 10, WarningDays: 40, NoticeDays: 90}
	h := Host{Name: "a"}
	lt := h.EffectiveLeadTimes(defaults)
	if lt != defaults {
		t.Fatalf("expected defaults passthrough, got %+v", lt)
	}
}

func TestHostEffectiveLeadTimesEmptyDefaults(t *testing.T) {
	h := Host{Name: "a"}
	lt := h.EffectiveLeadTimes(LeadTimes{})
	if lt != DefaultLeadTimes() {
		t.Fatalf("expected built-in defaults, got %+v", lt)
	}
}

func TestValidateRejectsEmptyInventory(t *testing.T) {
	inv := Inventory{}
	if err := inv.Validate(); err == nil {
		t.Fatal("expected error for empty inventory")
	}
}

func TestValidateRejectsEmptyName(t *testing.T) {
	inv := Inventory{Hosts: []Host{{Name: ""}}}
	if err := inv.Validate(); err == nil {
		t.Fatal("expected error for empty host name")
	}
}

func TestValidateRejectsBadPort(t *testing.T) {
	inv := Inventory{Hosts: []Host{{Name: "a", Port: 70000}}}
	if err := inv.Validate(); err == nil {
		t.Fatal("expected error for bad port")
	}
}

func TestValidateRejectsDuplicate(t *testing.T) {
	inv := Inventory{Hosts: []Host{{Name: "a"}, {Name: "a"}}}
	if err := inv.Validate(); err == nil {
		t.Fatal("expected error for duplicate host")
	}
}

func TestValidateAcceptsSameNameDifferentPort(t *testing.T) {
	inv := Inventory{Hosts: []Host{{Name: "a", Port: 443}, {Name: "a", Port: 8443}}}
	if err := inv.Validate(); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestParseYAML(t *testing.T) {
	data := []byte(`
defaults:
  critical_days: 5
hosts:
  - name: example.com
    owner: platform-team
  - name: internal.example.com
    port: 8443
    sni: example.com
    lead_times:
      critical_days: 1
`)
	inv, err := Parse(data, "inventory.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(inv.Hosts) != 2 {
		t.Fatalf("expected 2 hosts, got %d", len(inv.Hosts))
	}
	if inv.Hosts[0].Owner != "platform-team" {
		t.Fatalf("unexpected owner: %s", inv.Hosts[0].Owner)
	}
	if inv.Hosts[1].EffectiveSNI() != "example.com" {
		t.Fatalf("unexpected sni: %s", inv.Hosts[1].EffectiveSNI())
	}
}

func TestParseJSON(t *testing.T) {
	data := []byte(`{"hosts":[{"name":"example.com","team":"sre"}]}`)
	inv, err := Parse(data, "inventory.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if inv.Hosts[0].Team != "sre" {
		t.Fatalf("unexpected team: %s", inv.Hosts[0].Team)
	}
}

func TestParseJSONRejectsUnknownFields(t *testing.T) {
	data := []byte(`{"hosts":[{"name":"example.com"}],"bogus":true}`)
	if _, err := Parse(data, "inventory.json"); err == nil {
		t.Fatal("expected error for unknown field")
	}
}

func TestParseInvalidYAML(t *testing.T) {
	if _, err := Parse([]byte("not: [valid"), "inventory.yaml"); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestLoadFromDisk(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "inv.yaml")
	if err := os.WriteFile(p, []byte("hosts:\n  - name: example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	inv, err := Load(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(inv.Hosts) != 1 {
		t.Fatalf("expected 1 host, got %d", len(inv.Hosts))
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load("does-not-exist.yaml"); err == nil {
		t.Fatal("expected error for missing file")
	}
}
