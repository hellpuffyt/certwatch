package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// startTestTLSServer spins up a local TLS listener presenting a
// certificate matching opts, and returns its host:port. It never touches
// the network beyond loopback, keeping tests hermetic.
func startTestTLSServer(t *testing.T, notAfter time.Time) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	tmpl.Issuer = tmpl.Subject
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating cert: %v", err)
	}

	tlsCert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{tlsCert}})
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				buf := make([]byte, 1)
				conn.Read(buf)
				conn.Close()
			}()
		}
	}()

	return listener.Addr().String()
}

func writeInventory(t *testing.T, addr string) string {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "inventory.yaml")
	content := fmt.Sprintf("hosts:\n  - name: %s\n    port: %s\n    sni: localhost\n    owner: test-team\n", host, portStr)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func devNullFile(t *testing.T) *os.File {
	t.Helper()
	f, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func TestRun_HealthyHostExitsZero(t *testing.T) {
	addr := startTestTLSServer(t, time.Now().Add(90*24*time.Hour))
	invPath := writeInventory(t, addr)
	statePath := filepath.Join(t.TempDir(), "state.json")

	stdoutPath := filepath.Join(t.TempDir(), "out.txt")
	outFile, err := os.Create(stdoutPath)
	if err != nil {
		t.Fatal(err)
	}

	code := run([]string{
		"-inventory", invPath,
		"-state", statePath,
		"-format", "table",
	}, outFile, devNullFile(t))
	outFile.Close()

	if code != 0 {
		t.Fatalf("expected exit 0 for healthy host, got %d", code)
	}
	data, _ := os.ReadFile(stdoutPath)
	if !strings.Contains(string(data), "OK") {
		t.Fatalf("expected OK in output, got:\n%s", data)
	}
}

func TestRun_CriticalHostExitsNonZero(t *testing.T) {
	addr := startTestTLSServer(t, time.Now().Add(2*24*time.Hour))
	invPath := writeInventory(t, addr)
	statePath := filepath.Join(t.TempDir(), "state.json")

	code := run([]string{
		"-inventory", invPath,
		"-state", statePath,
		"-format", "table",
	}, devNullFile(t), devNullFile(t))

	if code != 1 {
		t.Fatalf("expected exit 1 for critical host, got %d", code)
	}
}

func TestRun_FailOnThresholdRespected(t *testing.T) {
	addr := startTestTLSServer(t, time.Now().Add(2*24*time.Hour))
	invPath := writeInventory(t, addr)
	statePath := filepath.Join(t.TempDir(), "state.json")

	// critical severity should not trip a fail-on=expired threshold
	code := run([]string{
		"-inventory", invPath,
		"-state", statePath,
		"-fail-on", "expired",
	}, devNullFile(t), devNullFile(t))

	if code != 0 {
		t.Fatalf("expected exit 0 when below fail-on threshold, got %d", code)
	}
}

func TestRun_MissingInventoryFlag(t *testing.T) {
	code := run([]string{}, devNullFile(t), devNullFile(t))
	if code != 2 {
		t.Fatalf("expected exit 2 for missing -inventory, got %d", code)
	}
}

func TestRun_InvalidInventoryPath(t *testing.T) {
	code := run([]string{"-inventory", "does-not-exist.yaml"}, devNullFile(t), devNullFile(t))
	if code != 2 {
		t.Fatalf("expected exit 2 for missing inventory file, got %d", code)
	}
}

func TestRun_InvalidFailOn(t *testing.T) {
	addr := startTestTLSServer(t, time.Now().Add(90*24*time.Hour))
	invPath := writeInventory(t, addr)
	code := run([]string{"-inventory", invPath, "-fail-on", "bogus"}, devNullFile(t), devNullFile(t))
	if code != 2 {
		t.Fatalf("expected exit 2 for invalid -fail-on, got %d", code)
	}
}

func TestRun_JSONOutputValid(t *testing.T) {
	addr := startTestTLSServer(t, time.Now().Add(90*24*time.Hour))
	invPath := writeInventory(t, addr)
	statePath := filepath.Join(t.TempDir(), "state.json")
	outPath := filepath.Join(t.TempDir(), "out.json")

	code := run([]string{
		"-inventory", invPath,
		"-state", statePath,
		"-format", "json",
		"-output", outPath,
	}, devNullFile(t), devNullFile(t))
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	var results []map[string]any
	if err := json.Unmarshal(data, &results); err != nil {
		t.Fatalf("expected valid JSON output: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
}

func TestRun_PrometheusOutputWritten(t *testing.T) {
	addr := startTestTLSServer(t, time.Now().Add(90*24*time.Hour))
	invPath := writeInventory(t, addr)
	statePath := filepath.Join(t.TempDir(), "state.json")
	promPath := filepath.Join(t.TempDir(), "metrics.prom")

	code := run([]string{
		"-inventory", invPath,
		"-state", statePath,
		"-prometheus-out", promPath,
	}, devNullFile(t), devNullFile(t))
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}
	data, err := os.ReadFile(promPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "certwatch_days_remaining") {
		t.Fatalf("expected prometheus metrics, got:\n%s", data)
	}
}

func TestRun_StatePersistedBetweenRuns(t *testing.T) {
	addr := startTestTLSServer(t, time.Now().Add(90*24*time.Hour))
	invPath := writeInventory(t, addr)
	statePath := filepath.Join(t.TempDir(), "state.json")

	run([]string{"-inventory", invPath, "-state", statePath}, devNullFile(t), devNullFile(t))
	if _, err := os.Stat(statePath); err != nil {
		t.Fatalf("expected state file to be created: %v", err)
	}
}

func TestRun_OnlyChangedSuppressesQuietRuns(t *testing.T) {
	addr := startTestTLSServer(t, time.Now().Add(90*24*time.Hour))
	invPath := writeInventory(t, addr)
	statePath := filepath.Join(t.TempDir(), "state.json")

	// First run: everything is new-but-OK, so nothing "changed" in the
	// problem sense; but there is no previous state either. We run twice
	// so the second run has stable prior state to compare against.
	out1 := filepath.Join(t.TempDir(), "out1.txt")
	f1, _ := os.Create(out1)
	run([]string{"-inventory", invPath, "-state", statePath, "-only-changed"}, f1, devNullFile(t))
	f1.Close()

	out2 := filepath.Join(t.TempDir(), "out2.txt")
	f2, _ := os.Create(out2)
	run([]string{"-inventory", invPath, "-state", statePath, "-only-changed"}, f2, devNullFile(t))
	f2.Close()

	data2, _ := os.ReadFile(out2)
	if len(data2) != 0 {
		t.Fatalf("expected second quiet run to suppress output, got:\n%s", data2)
	}
}

func TestRun_NoStateSkipsPersistence(t *testing.T) {
	addr := startTestTLSServer(t, time.Now().Add(90*24*time.Hour))
	invPath := writeInventory(t, addr)
	statePath := filepath.Join(t.TempDir(), "state.json")

	run([]string{"-inventory", invPath, "-state", statePath, "-no-state"}, devNullFile(t), devNullFile(t))
	if _, err := os.Stat(statePath); err == nil {
		t.Fatal("expected state file to not be created with -no-state")
	}
}

func TestRun_VersionFlag(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "out.txt")
	f, _ := os.Create(outPath)
	code := run([]string{"-version"}, f, devNullFile(t))
	f.Close()
	if code != 0 {
		t.Fatalf("expected exit 0 for -version, got %d", code)
	}
	data, _ := os.ReadFile(outPath)
	if !strings.Contains(string(data), version) {
		t.Fatalf("expected version string in output, got: %s", data)
	}
}

func TestRun_NowOverride(t *testing.T) {
	addr := startTestTLSServer(t, time.Now().Add(5*24*time.Hour))
	invPath := writeInventory(t, addr)
	statePath := filepath.Join(t.TempDir(), "state.json")
	outPath := filepath.Join(t.TempDir(), "out.json")

	// Jump "now" forward past the cert's expiry using -now.
	future := time.Now().Add(10 * 24 * time.Hour).Format(time.RFC3339)
	code := run([]string{
		"-inventory", invPath,
		"-state", statePath,
		"-format", "json",
		"-output", outPath,
		"-now", future,
	}, devNullFile(t), devNullFile(t))
	if code != 1 {
		t.Fatalf("expected non-zero exit for expired-by-override cert, got %d", code)
	}
	data, _ := os.ReadFile(outPath)
	if !strings.Contains(string(data), `"expired"`) {
		t.Fatalf("expected expired severity in output, got: %s", data)
	}
}

func TestRun_UnreachableHostDoesNotCrash(t *testing.T) {
	dir := t.TempDir()
	invPath := filepath.Join(dir, "inventory.yaml")
	// Port 1 on loopback should refuse immediately.
	if err := os.WriteFile(invPath, []byte("hosts:\n  - name: 127.0.0.1\n    port: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(dir, "state.json")

	code := run([]string{
		"-inventory", invPath,
		"-state", statePath,
		"-host-timeout", "2s",
		"-deadline", "5s",
		"-fail-on", "error",
	}, devNullFile(t), devNullFile(t))
	if code != 1 {
		t.Fatalf("expected exit 1 for unreachable host with fail-on=error, got %d", code)
	}
}
