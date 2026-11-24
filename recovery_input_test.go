package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/pauljones0/findcrypto/detector"
)

func TestReadProtectedPassphrase(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("protected passphrase input fails closed until Windows DACL validation exists")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "passphrase")
	if err := os.WriteFile(path, []byte("caf\u00e9 spaces  \r\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := readProtectedPassphrase(path)
	if err != nil {
		t.Fatal(err)
	}
	defer wipeMainBytes(got)
	if string(got) != "caf\u00e9 spaces  " {
		t.Fatalf("passphrase = %q", got)
	}
}

func TestReadProtectedPassphraseRefusals(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("content validation follows the Windows fail-closed platform check")
	}
	dir := t.TempDir()
	for name, raw := range map[string][]byte{
		"empty":     {},
		"emptyline": []byte("\n"),
		"bom":       []byte("\xef\xbb\xbfsecret\n"),
		"multiline": []byte("one\ntwo\n"),
		"nul":       []byte("one\x00two"),
		"utf8":      {0xff},
		"oversize":  bytes.Repeat([]byte{'x'}, protectedPassphraseMaxBytes+1),
	} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := readProtectedPassphrase(path); err == nil {
			t.Errorf("%s must fail", name)
		}
	}
	if _, err := readProtectedPassphrase(dir); err == nil {
		t.Error("directory must fail")
	}
	if runtime.GOOS != "windows" {
		permissive := filepath.Join(dir, "permissive")
		if err := os.WriteFile(permissive, []byte("secret"), 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := readProtectedPassphrase(permissive); err == nil || !strings.Contains(err.Error(), "owner-only") {
			t.Errorf("permissive file error = %v", err)
		}
		target := filepath.Join(dir, "target")
		if err := os.WriteFile(target, []byte("secret"), 0600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "link")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, err := readProtectedPassphrase(link); err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Errorf("symlink error = %v", err)
		}
	}
}

func TestReadProtectedPassphraseWindowsFailsClosed(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific DACL guard")
	}
	path := filepath.Join(t.TempDir(), "passphrase")
	if err := os.WriteFile(path, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readProtectedPassphrase(path); err == nil || !strings.Contains(err.Error(), "owner-only DACL") {
		t.Fatalf("Windows protected-file error = %v", err)
	}
}

func TestValidateRecoveryOutputPath(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "hits.jsonl")
	if err := os.WriteFile(input, []byte("evidence"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := validateRecoveryOutputPath(input, input); err == nil || !strings.Contains(err.Error(), "aliases input") {
		t.Fatalf("same-path error = %v", err)
	}

	hardlink := filepath.Join(dir, "hardlink.out")
	if err := os.Link(input, hardlink); err == nil {
		if err := validateRecoveryOutputPath(hardlink, input); err == nil || !strings.Contains(err.Error(), "same file") {
			t.Fatalf("hard-link error = %v", err)
		}
	}

	directory := filepath.Join(dir, "output-dir")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := validateRecoveryOutputPath(directory, input); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("directory error = %v", err)
	}

	if runtime.GOOS != "windows" {
		symlink := filepath.Join(dir, "output-link")
		if err := os.Symlink(input, symlink); err != nil {
			t.Fatal(err)
		}
		if err := validateRecoveryOutputPath(symlink, input); err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("symlink error = %v", err)
		}
	}

	regular := filepath.Join(dir, "identities.txt")
	if err := os.WriteFile(regular, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := validateRecoveryOutputPath(regular, input); err != nil {
		t.Fatalf("independent regular output: %v", err)
	}
	if err := validateRecoveryOutputPath(filepath.Join(dir, "new-identities.txt"), input); err != nil {
		t.Fatalf("new output: %v", err)
	}
}

func TestReadKnownAddressSetAndProfiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "known.txt")
	raw := "# public records\n0x9858effd232b4033e47d90003d41ec34ecaeda94\n" +
		"0x9858EfFD232B4033E47d90003D41EC34EcaEda94\n" +
		"cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0auqdal4\n"
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	set, err := readKnownAddressSet(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(set.values) != 2 || !set.matches("0x9858EfFD232B4033E47d90003D41EC34EcaEda94") {
		t.Fatalf("known set = %+v", set.values)
	}
	bitcoin, profiles, err := parseRecoveryProfiles("cosmos-hub,bitcoin-standard,cosmos-hub")
	if err != nil {
		t.Fatal(err)
	}
	if !bitcoin || len(profiles) != 1 || profiles[0] != detector.RecoveryProfileCosmos {
		t.Fatalf("profiles bitcoin=%v values=%v", bitcoin, profiles)
	}
	if _, _, err := parseRecoveryProfiles("unreviewed-wallet"); err == nil {
		t.Fatal("unknown profile must fail")
	}
}

func TestSeedRecoveryContextMatchesBitcoinAndEVM(t *testing.T) {
	words := strings.Split("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", " ")
	ctx := &seedRecoveryContext{
		includeBitcoin: true,
		profiles:       []string{detector.RecoveryProfileEVM},
		count:          1,
	}
	result, err := ctx.derive(words)
	if err != nil {
		t.Fatal(err)
	}
	if result.accounts == nil || len(result.addresses) != 7 {
		t.Fatalf("recovery = %+v", result)
	}
	set := &knownAddressSet{values: map[string]struct{}{
		"0x9858effd232b4033e47d90003d41ec34ecaeda94": {},
		"1lqbgskux5yyuonjxt5qgfpusxkyyweaba":         {},
	}}
	ctx.known = set
	matches := ctx.matches(result.addresses)
	// Base58 remains case-sensitive, so only the EVM entry matches.
	if len(matches) != 1 || matches[0].Profile != detector.RecoveryProfileEVM {
		t.Fatalf("matches = %+v", matches)
	}
}
