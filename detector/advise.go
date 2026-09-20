package detector

import (
	"bytes"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
)

// Guided mode (Goal 27, follow-up routing Goal 43): -advise inspects a
// target and recommends the documented-best command with reasons. It never
// scans content and never runs anything: inspection reads at most boot
// sectors, partition tables (Stat, OpenFS probes, ScanPartitions), and a
// bounded first-KB sniff for follow-up inputs (container magic, wallet
// records, extended public keys). The sniff runs strict validators over at
// most 1024 bytes at offset 0 — never a scan, never a run.
//
// Routing table (target shape → command):
//
//	directory                       → -walk (sweep every file)
//	EWF v1 container (E01/S01)      → raw scan (decodes the set directly)
//	EWF2 container (Ex01/Lx01)      → no command (libewf conversion pointer)
//	volume at offset 0              → -fs (deleted entries with filenames)
//	partitioned disk                → -fs (auto-seed, no -fs-offset needed)
//	wallet copy (mkey / keystore)   → -hashes (crack-ready hashes)
//	extended-public-key file        → -watch (offline addresses)
//	anything else                   → raw scan (every byte, no filenames)
//	empty / unreadable              → no command, reasons say why
//
// The shape table is unchanged: ambiguous input keeps the raw-scan
// default — a false diversion to a follow-up is worse than a raw scan.
// Filesystem targets also get an -unallocated-only follow-up; large
// raw targets get a -checkpoint follow-up. Follow-ups print under
// "Also consider" and never auto-run.

// Advice is a routing recommendation for one target.
type Advice struct {
	Target   string   // path as given
	Command  string   // recommended command line ("" when nothing to run)
	Reasons  []string // why this command (or why none)
	Also     []string // follow-up commands worth knowing
	scheme   string   // partition scheme for tests ("mbr"/"gpt"/"")
	partKind []string // probed volume kinds for tests
}

// adviseSniffMaxBytes bounds -advise content sniffing to the first KB at
// offset 0: container magic, wallet records, and extended public keys all
// identify from a prefix, so anything past this bound keeps the raw default.
const adviseSniffMaxBytes = 1024

// Advise inspects path and recommends the documented-best command.
// It reads at most boot sectors, partition tables, and the bounded
// first-KB sniff: content is never scanned and nothing is run.
func Advise(path string) (Advice, error) {
	ad := Advice{Target: path}
	fi, err := os.Stat(path)
	if err != nil {
		return ad, fmt.Errorf("cannot advise on %s: %w", path, err)
	}
	if fi.IsDir() {
		return adviseDir(path)
	}
	f, err := os.Open(path)
	if err != nil {
		return ad, fmt.Errorf("cannot advise on %s: %w", path, err)
	}
	defer f.Close()
	// The sniff head is read once with ReadAt so the shape probes below
	// see an undisturbed offset. A short or failed read simply yields no
	// sniff match and the raw default below.
	head := make([]byte, adviseSniffMaxBytes)
	nh, _ := f.ReadAt(head, 0)
	head = head[:nh]
	// Offset-0 container magic is definitive — no filesystem opens with
	// it — so it routes before the shape probes.
	if cad, ok := adviseContainer(path, head); ok {
		return cad, nil
	}
	if kind, _, err := OpenFS(f, 0); err == nil {
		ad.Command = fmt.Sprintf("findbtc -fs %s", shellQuote(path))
		ad.Reasons = []string{
			fmt.Sprintf("%s opens as %s at offset 0", path, kind),
			"deleted entries recover with filenames; live content scans raw anyway",
		}
		ad.Also = []string{
			fmt.Sprintf("findbtc -unallocated-only %s  (free space only, no filenames)", shellQuote(path)),
		}
		return ad, nil
	}
	if parts, perr := ScanPartitions(f); perr == nil && len(parts) > 0 {
		ad.scheme = parts[0].Scheme
		var kinds []string
		for _, p := range parts {
			if kind, _, err := OpenFS(f, p.Start); err == nil {
				kinds = append(kinds, kind)
			}
		}
		if len(kinds) > 0 {
			ad.partKind = kinds
			ad.Command = fmt.Sprintf("findbtc -fs %s", shellQuote(path))
			ad.Reasons = []string{
				fmt.Sprintf("%s table with %d partitions (%s)", strings.ToUpper(ad.scheme), len(parts), strings.Join(kinds, "+")),
				"auto-seed scans every supported volume; no -fs-offset needed",
			}
			ad.Also = []string{
				fmt.Sprintf("findbtc -unallocated-only %s  (free space only, no filenames)", shellQuote(path)),
			}
			return ad, nil
		}
		var descs []string
		for _, p := range parts {
			descs = append(descs, p.String())
		}
		sort.Strings(descs)
		return adviseRaw(path, fi, fmt.Sprintf("partition table holds %d entries (%s) but none opens as a supported filesystem", len(parts), strings.Join(descs, "; ")))
	}
	// No shape matched: sniff the bounded head for follow-up inputs
	// before falling back to the raw default.
	if fad, ok := adviseFollowup(path, head); ok {
		return fad, nil
	}
	return adviseRaw(path, fi, "no partition table or filesystem found")
}

// adviseContainer routes forensic containers by offset-0 magic: EWF v1
// sets (E01/S01) scan directly, EWF2 (Ex01/Lx01) needs conversion first.
// Anything else reports no match and the shape probes run as before.
func adviseContainer(path string, head []byte) (Advice, bool) {
	ad := Advice{Target: path}
	if len(head) >= len(ewf2Signature) && bytes.Equal(head[:len(ewf2Signature)], ewf2Signature) {
		ad.Reasons = []string{
			fmt.Sprintf("%s is an EWF2 image (Ex01/Lx01, EVF2 magic): only EWF v1 (E01) and SMART (S01) scan directly", path),
			fmt.Sprintf("convert first with libewf (ewfexport -u -t out -f raw %s) and scan the raw output", shellQuote(path)),
		}
		return ad, true
	}
	if len(head) >= len(ewfSignature) && bytes.Equal(head[:len(ewfSignature)], ewfSignature) {
		ad.Command = fmt.Sprintf("findbtc %s", shellQuote(path))
		ad.Reasons = []string{
			fmt.Sprintf("%s starts with EWF magic (%s container): the scan decodes it directly", path, ewfFlavorName(path)),
			"covers every decoded byte; hits lack filenames",
		}
		return ad, true
	}
	return ad, false
}

// ewfFlavorName names the container flavor from the segment extension:
// .E01-.E99 are EnCase, .S01-.S99 are SMART. Anything else stays generic.
func ewfFlavorName(path string) string {
	base := path
	if i := strings.LastIndexAny(base, `/\`); i >= 0 {
		base = base[i+1:]
	}
	if i := strings.LastIndexByte(base, '.'); i >= 0 {
		ext := strings.ToUpper(base[i+1:])
		if len(ext) == 3 && ext[1] >= '0' && ext[1] <= '9' && ext[2] >= '0' && ext[2] <= '9' {
			switch ext[0] {
			case 'E':
				return "EnCase E01"
			case 'S':
				return "SMART S01"
			}
		}
	}
	return "EWF v1"
}

// adviseFollowup sniffs the bounded head for follow-up inputs: encrypted
// wallet copies (a Bitcoin Core mkey record or a complete Ethereum
// keystore object) route to -hashes, extended-public-key files to -watch.
// Every check is a strict validator — the same one the routed mode runs —
// so near-misses and prose fall through to the raw default.
func adviseFollowup(path string, head []byte) (Advice, bool) {
	ad := Advice{Target: path}
	if mks := FindMasterKeys(head, 0); len(mks) > 0 {
		ad.Command = fmt.Sprintf("findbtc -hashes %s", shellQuote(path))
		ad.Reasons = []string{
			fmt.Sprintf("%s holds a Bitcoin Core mkey record at byte %d", path, mks[0].Offset()),
			"extract crack-ready hashes for hashcat/John (see docs/PASSWORD_RECOVERY.md)",
		}
		return ad, true
	}
	if kms := findKeystores(head, 0); len(kms) > 0 {
		ad.Command = fmt.Sprintf("findbtc -hashes %s", shellQuote(path))
		ad.Reasons = []string{
			fmt.Sprintf("%s holds a complete Ethereum keystore object at byte %d", path, kms[0].startAbs),
			"extract crack-ready hashes for hashcat/John (see docs/PASSWORD_RECOVERY.md)",
		}
		return ad, true
	}
	if pubs, _ := ExtractXpubs(head); len(pubs) > 0 {
		// Only a key -watch itself accepts earns the route: checksum
		// shape alone is not enough (curve, compression, depth rules).
		for _, s := range pubs {
			if x, err := ParseXPub(s); err == nil {
				ad.Command = fmt.Sprintf("findbtc -watch %s", shellQuote(path))
				ad.Reasons = []string{
					fmt.Sprintf("%s holds a checksum-valid %s extended public key (fingerprint %s)", path, x.Label, x.Fingerprint()),
					"derive watch-only addresses offline (see docs/WATCH_ONLY.md)",
				}
				return ad, true
			}
		}
	}
	return ad, false
}

// adviseDir routes directories to -walk.
func adviseDir(path string) (Advice, error) {
	ad := Advice{Target: path}
	d, err := os.Open(path)
	if err != nil {
		return ad, fmt.Errorf("cannot advise on %s: %w", path, err)
	}
	defer d.Close()
	names, err := d.Readdirnames(1)
	if err != nil || len(names) == 0 {
		ad.Reasons = []string{fmt.Sprintf("%s is an empty directory: nothing to scan", path)}
		return ad, nil
	}
	ad.Command = fmt.Sprintf("findbtc -walk %s", shellQuote(path))
	ad.Reasons = []string{
		fmt.Sprintf("%s is a directory", path),
		"sweeps every regular file with the standard detectors (symlinks not followed unless -walk-follow-symlinks)",
	}
	return ad, nil
}

// adviseRaw routes files and devices without usable filesystem
// structure to a raw scan.
func adviseRaw(path string, fi os.FileInfo, why string) (Advice, error) {
	ad := Advice{Target: path}
	size := fi.Size()
	if size == 0 && fi.Mode().IsRegular() {
		ad.Reasons = []string{fmt.Sprintf("%s is empty (0 bytes): nothing to scan", path)}
		return ad, nil
	}
	sizeNote := ""
	if size > 0 {
		sizeNote = fmt.Sprintf(" (%s)", humanBytes(size))
	} else if sz, err := FileSize(path); err == nil && sz > 0 {
		sizeNote = fmt.Sprintf(" (%s)", humanBytes(sz))
		size = sz
	}
	ad.Command = fmt.Sprintf("findbtc %s", shellQuote(path))
	ad.Reasons = []string{
		fmt.Sprintf("%s%s: %s", path, sizeNote, why),
		"raw scan covers every byte; hits lack filenames",
	}
	if size >= 1<<30 {
		ad.Also = []string{
			fmt.Sprintf("findbtc -checkpoint resume.journal %s  (interruptible: resume with -resume)", shellQuote(path)),
		}
	}
	return ad, nil
}

// shellQuote quotes path only when it needs it.
// shellQuote renders path for paste into the platform's interactive
// shell. Advice is copy/paste output, so the quoting must survive a
// real shell round-trip — never Go syntax (whose doubled
// backslashes no shell unpicks).
func shellQuote(path string) string {
	if runtime.GOOS == "windows" {
		return quotePowerShell(path)
	}
	return quoteUnix(path)
}

// quoteUnix single-quotes paths holding shell-special characters,
// escaping embedded single quotes. Backslashes, dollars, and
// backticks are literal inside single quotes in sh, bash, zsh, and
// fish alike, and so is a newline — which must still trigger
// quoting, since a bare newline is a command separator (a bare CR
// round-trips, but quoting only the true boundary keeps output
// readable).
func quoteUnix(path string) string {
	if !strings.ContainsAny(path, " \t\n\"'\\$`!()[]{}<>|;&*#?~") {
		return path
	}
	return "'" + strings.ReplaceAll(path, "'", `'\''`) + "'"
}

// quotePowerShell renders path for paste into PowerShell (the
// labeled Windows shell; cmd.exe would take the quotes literally).
// Single-quoted strings are fully literal in PowerShell — no $,
// backtick, %, or wildcard expansion — per about_Quoting_Rules, so
// over-quoting is always safe and the trigger set stays broad.
//
// Two repairs from real powershell.exe evidence (Goal 40):
//   - A trailing backslash is stripped (roots like C:\ kept): the
//     separator is insignificant to the target, but PowerShell's
//     native command-line rebuild wraps spaced args in "..." without
//     escaping it, so argv would end in a literal quote. Stripping is
//     version-proof; doubling would differ between 5.1 and 7.3+.
//   - LF/CR (illegal in Win32 names, but quotable input) use the
//     double-quote form with backtick escapes: a literal newline
//     inside single quotes would start a new PowerShell statement —
//     a paste-time command injection — while `"a`nb"` parses to the
//     exact string.
func quotePowerShell(path string) string {
	if path == "" {
		return "''"
	}
	if len(path) > 3 {
		path = strings.TrimRight(path, `\`)
		if path == "" {
			return "''"
		}
	}
	if strings.ContainsAny(path, "\r\n") {
		var b strings.Builder
		b.WriteByte('"')
		for _, r := range path {
			switch r {
			case '`':
				b.WriteString("``")
			case '$':
				b.WriteString("`$")
			case '"':
				b.WriteString("`\"")
			case '\r':
				b.WriteString("`r")
			case '\n':
				b.WriteString("`n")
			default:
				b.WriteRune(r)
			}
		}
		b.WriteByte('"')
		return b.String()
	}
	if !strings.ContainsAny(path, " \t'\"$`&|<>(){}[];,@#%*?!^=+") {
		return path
	}
	return "'" + strings.ReplaceAll(path, "'", "''") + "'"
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for n/div >= unit && exp < 3 {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGT"[exp])
}
