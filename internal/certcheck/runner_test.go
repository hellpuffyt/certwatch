package certcheck

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"certwatch/internal/inventory"
)

// fakeFetcher is a Fetcher test double keyed by host name, so tests never
// touch the network.
type fakeFetcher struct {
	byName      map[string]CertInfo
	errByName   map[string]error
	delay       time.Duration
	calls       int32
	maxInFlight int32
	inFlight    int32
}

func (f *fakeFetcher) Fetch(ctx context.Context, host inventory.Host) (CertInfo, error) {
	atomic.AddInt32(&f.calls, 1)
	cur := atomic.AddInt32(&f.inFlight, 1)
	defer atomic.AddInt32(&f.inFlight, -1)
	for {
		max := atomic.LoadInt32(&f.maxInFlight)
		if cur <= max || atomic.CompareAndSwapInt32(&f.maxInFlight, max, cur) {
			break
		}
	}

	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return CertInfo{}, ctx.Err()
		}
	}
	if err, ok := f.errByName[host.Name]; ok {
		return CertInfo{}, err
	}
	if info, ok := f.byName[host.Name]; ok {
		return info, nil
	}
	return CertInfo{}, fmt.Errorf("no fixture for %s", host.Name)
}

func okInfo(days int) CertInfo {
	now := time.Now()
	return CertInfo{
		NotBefore: now.Add(-24 * time.Hour),
		NotAfter:  now.Add(time.Duration(days) * 24 * time.Hour),
		DNSNames:  []string{"placeholder"},
	}
}

func TestRun_AllHealthy(t *testing.T) {
	hosts := []inventory.Host{{Name: "a"}, {Name: "b"}, {Name: "c"}}
	f := &fakeFetcher{byName: map[string]CertInfo{
		"a": {NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(100 * 24 * time.Hour), DNSNames: []string{"a"}},
		"b": {NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(100 * 24 * time.Hour), DNSNames: []string{"b"}},
		"c": {NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(100 * 24 * time.Hour), DNSNames: []string{"c"}},
	}}
	results := Run(context.Background(), f, hosts, RunOptions{})
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
	for i, r := range results {
		if r.Severity != SeverityOK {
			t.Fatalf("result %d: expected OK, got %s (%s)", i, r.Severity, r.Error)
		}
	}
}

func TestRun_PreservesOrder(t *testing.T) {
	hosts := []inventory.Host{{Name: "z"}, {Name: "m"}, {Name: "a"}}
	f := &fakeFetcher{byName: map[string]CertInfo{
		"z": okInfo(100), "m": okInfo(100), "a": okInfo(100),
	}}
	results := Run(context.Background(), f, hosts, RunOptions{})
	if results[0].Host != "z" || results[1].Host != "m" || results[2].Host != "a" {
		t.Fatalf("expected results in inventory order, got %v %v %v", results[0].Host, results[1].Host, results[2].Host)
	}
}

func TestRun_OneFailingHostDoesNotPoisonRun(t *testing.T) {
	hosts := []inventory.Host{{Name: "good1"}, {Name: "bad"}, {Name: "good2"}}
	f := &fakeFetcher{
		byName: map[string]CertInfo{
			"good1": okInfo(100),
			"good2": okInfo(100),
		},
		errByName: map[string]error{
			"bad": errors.New("connection refused"),
		},
	}
	results := Run(context.Background(), f, hosts, RunOptions{})
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
	byHost := map[string]Result{}
	for _, r := range results {
		byHost[r.Host] = r
	}
	if byHost["good1"].Severity != SeverityOK {
		t.Fatalf("expected good1 OK, got %s", byHost["good1"].Severity)
	}
	if byHost["good2"].Severity != SeverityOK {
		t.Fatalf("expected good2 OK, got %s", byHost["good2"].Severity)
	}
	if byHost["bad"].Severity != SeverityError {
		t.Fatalf("expected bad to be SeverityError, got %s", byHost["bad"].Severity)
	}
	if byHost["bad"].Error == "" {
		t.Fatal("expected error message on failing host")
	}
}

func TestRun_RespectsConcurrencyLimit(t *testing.T) {
	hosts := make([]inventory.Host, 20)
	byName := map[string]CertInfo{}
	for i := range hosts {
		name := fmt.Sprintf("host%d", i)
		hosts[i] = inventory.Host{Name: name}
		byName[name] = okInfo(100)
	}
	f := &fakeFetcher{byName: byName, delay: 30 * time.Millisecond}
	results := Run(context.Background(), f, hosts, RunOptions{Concurrency: 4})
	if len(results) != 20 {
		t.Fatalf("expected 20 results, got %d", len(results))
	}
	if f.maxInFlight > 4 {
		t.Fatalf("expected at most 4 concurrent fetches, saw %d", f.maxInFlight)
	}
	if f.maxInFlight < 2 {
		t.Fatalf("expected some real concurrency, saw max in-flight %d", f.maxInFlight)
	}
}

func TestRun_PerHostTimeout(t *testing.T) {
	hosts := []inventory.Host{{Name: "slow"}}
	f := &fakeFetcher{
		byName: map[string]CertInfo{"slow": okInfo(100)},
		delay:  200 * time.Millisecond,
	}
	start := time.Now()
	results := Run(context.Background(), f, hosts, RunOptions{PerHostTimeout: 20 * time.Millisecond})
	elapsed := time.Since(start)
	if results[0].Severity != SeverityError {
		t.Fatalf("expected timeout to produce SeverityError, got %s", results[0].Severity)
	}
	if elapsed > time.Second {
		t.Fatalf("expected fast timeout, took %v", elapsed)
	}
}

func TestRun_OverallDeadlineDoesNotHang(t *testing.T) {
	hosts := []inventory.Host{{Name: "a"}, {Name: "b"}, {Name: "c"}}
	byName := map[string]CertInfo{"a": okInfo(100), "b": okInfo(100), "c": okInfo(100)}
	f := &fakeFetcher{byName: byName, delay: 500 * time.Millisecond}
	start := time.Now()
	results := Run(context.Background(), f, hosts, RunOptions{Concurrency: 1, PerHostTimeout: 5 * time.Second, Deadline: 50 * time.Millisecond})
	elapsed := time.Since(start)
	if len(results) != 3 {
		t.Fatalf("expected 3 results even under deadline, got %d", len(results))
	}
	if elapsed > 2*time.Second {
		t.Fatalf("expected run to respect overall deadline, took %v", elapsed)
	}
	sawError := false
	for _, r := range results {
		if r.Severity == SeverityError {
			sawError = true
		}
	}
	if !sawError {
		t.Fatal("expected at least one host to be cut off by the deadline")
	}
}

func TestRun_UsesProvidedNow(t *testing.T) {
	fixed := time.Date(2030, 6, 1, 0, 0, 0, 0, time.UTC)
	hosts := []inventory.Host{{Name: "a"}}
	f := &fakeFetcher{byName: map[string]CertInfo{
		"a": {NotBefore: fixed.Add(-time.Hour), NotAfter: fixed.Add(5 * 24 * time.Hour), DNSNames: []string{"a"}},
	}}
	results := Run(context.Background(), f, hosts, RunOptions{Now: fixed})
	if !results[0].CheckedAt.Equal(fixed) {
		t.Fatalf("expected CheckedAt to equal provided now, got %v", results[0].CheckedAt)
	}
	if results[0].Severity != SeverityCritical {
		t.Fatalf("expected critical severity relative to provided now, got %s", results[0].Severity)
	}
}

func TestRun_EmptyInventory(t *testing.T) {
	f := &fakeFetcher{byName: map[string]CertInfo{}}
	results := Run(context.Background(), f, nil, RunOptions{})
	if len(results) != 0 {
		t.Fatalf("expected 0 results for empty inventory, got %d", len(results))
	}
}
