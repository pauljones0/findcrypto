package detector

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Atomic carve outputs commit whole files: content lands exactly,
// no staging litter survives, and reaps only touch our prefix.
func TestWriteFileAtomicRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if err := writeFileAtomic(dir, "hit-000001.bin", []byte("bytes")); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "hit-000001.bin"))
	if err != nil || string(raw) != "bytes" {
		t.Fatalf("round trip: %q, %v", raw, err)
	}
	if n := CleanCarveTemps(dir); n != 0 {
		t.Errorf("reaped %d, want 0 (nothing staged)", n)
	}
	// Overwrite commits too (fresh run into a dirty dir).
	if err := os.Chmod(filepath.Join(dir, "hit-000001.bin"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(dir, "hit-000001.bin", []byte("new")); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(filepath.Join(dir, "hit-000001.bin"))
	if string(raw) != "new" {
		t.Errorf("overwrite left %q", raw)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(dir, "hit-000001.bin"))
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0600 {
			t.Errorf("atomic output mode = %04o, want 0600", got)
		}
	}
}

// Patch attribution rewrites sidecars after the scan. The rewrite must keep
// the carve pipeline's private, atomic-output contract because --reveal can
// place seed words in this JSON.
func TestRewritePatchSidecarAtomicPrivate(t *testing.T) {
	dir := t.TempDir()
	carve := filepath.Join(dir, "hit-000001.bin")
	sidecar := sidecarPathFor(carve)
	if err := os.WriteFile(sidecar, []byte("stale"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sidecar, 0644); err != nil {
		t.Fatal(err)
	}
	dets := []Detection{{
		Needle:    "bip39-12",
		CarvePath: carve,
		Commit:    "0123456789abcdef",
		Words:     []string{"abandon", "about"},
	}}
	rewritePatchSidecars(dets, io.Discard)
	raw, err := os.ReadFile(sidecar)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"words"`) || !strings.Contains(string(raw), `"abandon"`) {
		t.Fatalf("rewritten sidecar lacks detection: %s", raw)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(sidecar)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0600 {
			t.Errorf("rewritten sidecar mode = %04o, want 0600", got)
		}
	}
	if n := CleanCarveTemps(dir); n != 0 {
		t.Errorf("rewrite left %d staging files", n)
	}
}

func TestCleanCarveTemps(t *testing.T) {
	dir := t.TempDir()
	keep := filepath.Join(dir, "hit-000001.bin")
	if err := os.WriteFile(keep, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(dir, carveTempPrefix+"12345")
	if err := os.WriteFile(stale, []byte("torn"), 0644); err != nil {
		t.Fatal(err)
	}
	if n := CleanCarveTemps(dir); n != 1 {
		t.Errorf("reaped %d, want 1", n)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Errorf("real carve reaped: %v", err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("staging file survives: %v", err)
	}
	if n := CleanCarveTemps(filepath.Join(dir, "missing")); n != 0 {
		t.Errorf("missing dir reaped %d, want 0", n)
	}
}
