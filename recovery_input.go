package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unicode/utf8"

	"github.com/pauljones0/findcrypto/detector"
)

const (
	recoveryProfileBitcoin        = "bitcoin-standard"
	protectedPassphraseMaxBytes   = 4096
	knownAddressesMaxBytes        = 1 << 20
	knownAddressesMaxEntries      = 10000
	recoveryDerivationWorkMaximum = 100000
)

type seedCompleteOptions struct {
	OutPath            string
	Max                int
	KnownAddressesPath string
	PassphrasePath     string
	ProfileList        string
	Start              uint32
	Count              int
}

type seedRecoveryContext struct {
	passphrase     []byte
	known          *knownAddressSet
	includeBitcoin bool
	profiles       []string
	start          uint32
	count          int
}

func (o seedCompleteOptions) loadRecoveryContext() (*seedRecoveryContext, error) {
	ctx := &seedRecoveryContext{start: o.Start, count: o.Count}
	if o.PassphrasePath != "" {
		passphrase, err := readProtectedPassphrase(o.PassphrasePath)
		if err != nil {
			return nil, err
		}
		ctx.passphrase = passphrase
	}
	fail := func(err error) (*seedRecoveryContext, error) {
		wipeMainBytes(ctx.passphrase)
		return nil, err
	}
	if o.KnownAddressesPath != "" {
		known, err := readKnownAddressSet(o.KnownAddressesPath)
		if err != nil {
			return fail(err)
		}
		ctx.known = known
	}
	includeBitcoin, profiles, err := parseRecoveryProfiles(o.ProfileList)
	if err != nil {
		return fail(err)
	}
	ctx.includeBitcoin, ctx.profiles = includeBitcoin, profiles
	if !ctx.includeBitcoin && len(ctx.profiles) == 0 {
		return fail(fmt.Errorf("no recovery profiles selected"))
	}
	return ctx, nil
}

func (c *seedRecoveryContext) close() {
	if c != nil {
		wipeMainBytes(c.passphrase)
	}
}

func (c *seedRecoveryContext) workPerCandidate() int {
	profiles := len(c.profiles)
	if c.includeBitcoin {
		profiles += 6 // BIP44/49/84, external + change.
	}
	return profiles * c.count
}

func parseRecoveryProfiles(csv string) (bool, []string, error) {
	all := append([]string{recoveryProfileBitcoin}, detector.SupportedRecoveryProfiles()...)
	requested := all
	if strings.TrimSpace(csv) != "" {
		requested = strings.Split(csv, ",")
	}
	valid := make(map[string]bool, len(all))
	for _, name := range all {
		valid[name] = true
	}
	seen := make(map[string]bool, len(requested))
	includeBitcoin := false
	var profiles []string
	for _, raw := range requested {
		name := strings.ToLower(strings.TrimSpace(raw))
		if !valid[name] {
			return false, nil, fmt.Errorf("unknown recovery profile %q (want %s)", raw, strings.Join(all, ","))
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		if name == recoveryProfileBitcoin {
			includeBitcoin = true
		} else {
			profiles = append(profiles, name)
		}
	}
	return includeBitcoin, profiles, nil
}

type candidateRecovery struct {
	accounts  *detector.SeedAccounts
	addresses []detector.RecoveryAddress
}

func (c *seedRecoveryContext) derive(words []string) (*candidateRecovery, error) {
	result := &candidateRecovery{}
	if c.includeBitcoin {
		accounts, err := detector.SeedToAccountsWithPassphrase(words, c.passphrase)
		if err != nil {
			return nil, err
		}
		result.accounts = accounts
		entries, err := detector.CollectWatchAddrsRange(
			[]string{accounts.XPub44, accounts.YPub49, accounts.ZPub84}, c.start, c.count)
		if err != nil {
			return nil, err
		}
		purpose := map[string]uint32{"xpub": 44, "ypub": 49, "zpub": 84}
		for _, entry := range entries {
			result.addresses = append(result.addresses, detector.RecoveryAddress{
				Chain:   "bitcoin",
				Profile: recoveryProfileBitcoin,
				Path:    fmt.Sprintf("m/%d'/0'/0'/%d/%d", purpose[entry.Version], entry.Chain, entry.Index),
				Index:   entry.Index,
				Address: entry.Address,
			})
		}
	}
	if len(c.profiles) > 0 {
		addresses, err := detector.SeedToRecoveryAddressesWithOptions(words, detector.RecoveryOptions{
			Passphrase: c.passphrase,
			Profiles:   c.profiles,
			Start:      c.start,
			Count:      c.count,
		})
		if err != nil {
			return nil, err
		}
		result.addresses = append(result.addresses, addresses...)
	}
	return result, nil
}

func (c *seedRecoveryContext) matches(addresses []detector.RecoveryAddress) []detector.RecoveryAddress {
	if c.known == nil {
		return addresses
	}
	var matches []detector.RecoveryAddress
	for _, address := range addresses {
		if c.known.matches(address.Address) {
			matches = append(matches, address)
		}
	}
	return matches
}

type knownAddressSet struct {
	values map[string]struct{}
}

func (s *knownAddressSet) matches(address string) bool {
	canonical, err := detector.CanonicalKnownAddress(address)
	if err != nil {
		return false
	}
	_, ok := s.values[canonical]
	return ok
}

func readKnownAddressSet(path string) (*knownAddressSet, error) {
	raw, err := readBoundedRegularFile(path, knownAddressesMaxBytes, false)
	if err != nil {
		return nil, fmt.Errorf("known-address file: %w", err)
	}
	if !utf8.Valid(raw) {
		return nil, fmt.Errorf("known-address file is not valid UTF-8")
	}
	set := &knownAddressSet{values: make(map[string]struct{})}
	for i, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		canonical, err := detector.CanonicalKnownAddress(line)
		if err != nil {
			return nil, fmt.Errorf("known-address file line %d: %w", i+1, err)
		}
		set.values[canonical] = struct{}{}
		if len(set.values) > knownAddressesMaxEntries {
			return nil, fmt.Errorf("known-address file exceeds %d unique entries", knownAddressesMaxEntries)
		}
	}
	if len(set.values) == 0 {
		return nil, fmt.Errorf("known-address file contains no addresses")
	}
	return set, nil
}

func readProtectedPassphrase(path string) ([]byte, error) {
	if runtime.GOOS == "windows" {
		return nil, fmt.Errorf("BIP39 passphrase files are not supported on Windows: findcrypto cannot verify an owner-only DACL; use a supported Unix host for protected passphrase recovery")
	}
	raw, err := readBoundedRegularFile(path, protectedPassphraseMaxBytes, true)
	if err != nil {
		return nil, fmt.Errorf("BIP39 passphrase file: %w", err)
	}
	fail := func(err error) ([]byte, error) {
		wipeMainBytes(raw)
		return nil, err
	}
	end := len(raw)
	if end >= 2 && raw[end-2] == '\r' && raw[end-1] == '\n' {
		end -= 2
	} else if end >= 1 && raw[end-1] == '\n' {
		end--
	}
	passphrase := raw[:end]
	if len(passphrase) == 0 {
		return fail(fmt.Errorf("BIP39 passphrase file is empty; omit -bip39-passphrase-file to derive with the standard empty passphrase"))
	}
	if bytes.HasPrefix(passphrase, []byte{0xef, 0xbb, 0xbf}) {
		return fail(fmt.Errorf("BIP39 passphrase file begins with a UTF-8 BOM; save it as UTF-8 without BOM so invisible bytes cannot change the wallet"))
	}
	if bytes.IndexByte(passphrase, 0) >= 0 {
		return fail(fmt.Errorf("BIP39 passphrase file contains NUL"))
	}
	if bytes.IndexByte(passphrase, '\n') >= 0 || bytes.IndexByte(passphrase, '\r') >= 0 {
		return fail(fmt.Errorf("BIP39 passphrase file must contain exactly one line"))
	}
	if !utf8.Valid(passphrase) {
		return fail(fmt.Errorf("BIP39 passphrase file is not valid UTF-8"))
	}
	out := append([]byte(nil), passphrase...)
	wipeMainBytes(raw)
	return out, nil
}

func readBoundedRegularFile(path string, maxBytes int64, ownerOnly bool) ([]byte, error) {
	if path == "" || path == "-" {
		return nil, fmt.Errorf("need a regular file path, not stdin")
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("refusing symlink %s", path)
	}
	if !before.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return nil, fmt.Errorf("%s changed while opening", path)
	}
	if ownerOnly && runtime.GOOS != "windows" && opened.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("%s permissions are %04o; require owner-only 0600 or stricter", path, opened.Mode().Perm())
	}
	if opened.Size() > maxBytes {
		return nil, fmt.Errorf("%s is %d bytes; maximum is %d", path, opened.Size(), maxBytes)
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		wipeMainBytes(raw)
		return nil, err
	}
	if int64(len(raw)) > maxBytes {
		wipeMainBytes(raw)
		return nil, fmt.Errorf("%s grew past %d bytes while reading", path, maxBytes)
	}
	return raw, nil
}

// validateRecoveryOutputPath keeps the atomic recovery handoff from replacing
// an input report, known-address list, or protected passphrase. It checks both
// cleaned path equality and existing inode identity, since hard links and
// symlinked input paths can spell the same file differently. Existing output
// targets must be regular files; unlike the generic sensitive-output helper,
// recovery refuses to remove a symlink, device, FIFO, or socket by renaming
// over it.
func validateRecoveryOutputPath(output string, inputs ...string) error {
	if output == "" {
		return nil
	}
	outputAbs, err := filepath.Abs(output)
	if err != nil {
		return fmt.Errorf("resolve recovery output %s: %w", output, err)
	}
	outputAbs = filepath.Clean(outputAbs)
	outputInfo, outputErr := os.Lstat(output)
	if outputErr != nil && !os.IsNotExist(outputErr) {
		return fmt.Errorf("inspect recovery output %s: %w", output, outputErr)
	}
	outputExists := outputErr == nil
	if outputExists && !outputInfo.Mode().IsRegular() {
		return fmt.Errorf("refusing recovery output %s: existing target is not a regular file", output)
	}

	for _, input := range inputs {
		if input == "" || input == "-" {
			continue
		}
		inputAbs, err := filepath.Abs(input)
		if err != nil {
			return fmt.Errorf("resolve recovery input %s: %w", input, err)
		}
		if outputAbs == filepath.Clean(inputAbs) {
			return fmt.Errorf("refusing recovery output %s: it aliases input %s", output, input)
		}
		if !outputExists {
			continue
		}
		inputInfo, err := os.Stat(input)
		if err != nil {
			// Input validation reports a more useful missing/unreadable-file
			// error later. Path equality above still catches the dangerous
			// same-name case even when the input disappeared after reading.
			continue
		}
		if os.SameFile(outputInfo, inputInfo) {
			return fmt.Errorf("refusing recovery output %s: it is the same file as input %s", output, input)
		}
	}
	return nil
}

func wipeMainBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
