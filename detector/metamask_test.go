package detector

import (
	"math/rand"
	"os"
	"strings"
	"testing"
)

// Browser-passworder fixtures shaped per @metamask/browser-passworder: data/iv
// base64 (AES-GCM), iv 16 bytes, salt base64 of 32 bytes, new format with a
// PBKDF2 keyMetadata object. Payload bytes are random, not a real vault.

const browserPassworderData = "eOZFLylpzM3CcQyDhp7LeXn+P6HtZyydU4gAyyUUqS+TeRgYxu1TcoG0q02cr0wkJS82F1/R54k/3UTPwPnv4ycvhbFif2uiZ6u4CsuGbpg0B3H7cr1qZbhd+vaqePdzlndnp1OXKb1+hJWdOA1rpmeIUSimWIWfhBbXA9Bl6tS2/kOHi5MrENO9Pg9liiAJC32xMI8rK+E4+u89JZKAmRR+swfAHDLHrmjEdhP2h1O4pcZwIx5Jl+1NqdfqlAAyYFHlhEYz0Ds="
const browserPassworderIV = "bSXPc0xJod0nPk2Pq19b2w=="
const browserPassworderSalt = "jRCZ7AXo/cfB1zR3dkirc73iAYJQReTaMtpelnlrnTA="

var browserPassworderOldVault = `{"data": "` + browserPassworderData + `", "iv": "` + browserPassworderIV + `", "salt": "` + browserPassworderSalt + `"}`

var browserPassworderNewVault = `{"data": "` + browserPassworderData + `", "iv": "` + browserPassworderIV + `", "keyMetadata": {"algorithm": "PBKDF2", "params": {"iterations": 900000}}, "salt": "` + browserPassworderSalt + `"}`

func TestFindBrowserPassworderVaults(t *testing.T) {
	for name, vault := range map[string]string{"old": browserPassworderOldVault, "new": browserPassworderNewVault} {
		buf := []byte("xx " + vault + " yy")
		matches := findBrowserPassworderVaults(buf, 700)
		if len(matches) != 1 {
			t.Fatalf("%s: got %d matches, want 1", name, len(matches))
		}
		span := buf[matches[0].startAbs-700 : matches[0].endAbs-700]
		if string(span) != vault || !strings.Contains(string(span), browserPassworderIV) {
			t.Errorf("%s: match span misses the vault", name)
		}
	}
	// LevelDB form: the vault JSON-escaped inside an outer object.
	escaped := `{"KeyringController": {"vault": "` + escapeJSON(browserPassworderOldVault) + `"}}`
	if m := findBrowserPassworderVaults([]byte(escaped), 0); len(m) != 1 {
		t.Errorf("escaped vault: %d matches, want 1", len(m))
	}
	// Raw LevelDB values can expose only the escaped object fragment.
	if m := findBrowserPassworderVaults([]byte(escapeJSON(browserPassworderOldVault)), 0); len(m) != 1 {
		t.Errorf("escaped fragment: %d matches, want 1", len(m))
	}
	// Wrong iv length is not a vault.
	dud := `{"data": "` + browserPassworderData + `", "iv": "aGk=", "salt": "` + browserPassworderSalt + `"}`
	if m := findBrowserPassworderVaults([]byte(dud), 0); len(m) != 0 {
		t.Error("short iv must stay silent")
	}
	// Missing salt is not a vault.
	dud2 := `{"data": "` + browserPassworderData + `", "iv": "` + browserPassworderIV + `"}`
	if m := findBrowserPassworderVaults([]byte(dud2), 0); len(m) != 0 {
		t.Error("missing salt must stay silent")
	}
	// Non-base64 data is not a vault.
	dud3 := `{"data": "!!!not-base64!!!", "iv": "` + browserPassworderIV + `", "salt": "` + browserPassworderSalt + `"}`
	if m := findBrowserPassworderVaults([]byte(dud3), 0); len(m) != 0 {
		t.Error("non-base64 data must stay silent")
	}
}

func escapeJSON(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return strings.ReplaceAll(s, `"`, `\"`)
}

func TestBrowserPassworderFieldsMustShareObject(t *testing.T) {
	plain := `{"data":"` + browserPassworderData + `"}` +
		` {"iv":"` + browserPassworderIV + `"}` +
		` {"salt":"` + browserPassworderSalt + `"}`
	escaped := `{"dataOnly":"` + escapeJSON(`{"data":"`+browserPassworderData+`"}`) +
		`","ivOnly":"` + escapeJSON(`{"iv":"`+browserPassworderIV+`"}`) +
		`","saltOnly":"` + escapeJSON(`{"salt":"`+browserPassworderSalt+`"}`) + `"}`
	for name, raw := range map[string]string{"plain": plain, "escaped": escaped} {
		t.Run(name, func(t *testing.T) {
			if matches := findBrowserPassworderVaults([]byte(raw), 0); len(matches) != 0 {
				t.Fatalf("separate objects produced matches: %+v", matches)
			}
		})
	}
}

func TestBrowserPassworderEarlierDecoyDoesNotHideVault(t *testing.T) {
	decoy := `{"data":"not-base64","salt":"also-not-base64"} `
	raw := []byte(decoy + browserPassworderOldVault)
	matches := findBrowserPassworderVaults(raw, 400)
	if len(matches) != 1 {
		t.Fatalf("matches = %+v, want the valid vault after the decoy", matches)
	}
	if want := int64(400 + len(decoy)); matches[0].startAbs != want {
		t.Fatalf("match starts at %d, want %d", matches[0].startAbs, want)
	}
	escaped := `{"note":"an escaped quote: \"","vault":"` + escapeJSON(browserPassworderOldVault) + `"}`
	if matches := findBrowserPassworderVaults([]byte(escaped), 0); len(matches) != 1 {
		t.Fatalf("escaped decoy hid valid vault: %+v", matches)
	}
}

func TestBrowserPassworderDenseAnchorsAndUnmatchedBraces(t *testing.T) {
	// This used to trigger a backwards 2 KiB brace walk for every iv anchor.
	// The unmatched opens also prove the bounded streaming stack retains the
	// later complete object without retaining all earlier brace positions.
	noise := strings.Repeat(`{"iv"`, 1<<15)
	raw := []byte(noise + browserPassworderOldVault)
	matches := findBrowserPassworderVaults(raw, 900)
	if len(matches) != 1 {
		t.Fatalf("dense damaged prefix produced matches %+v, want one valid trailing vault", matches)
	}
	if want := int64(900 + len(noise)); matches[0].startAbs != want {
		t.Fatalf("match starts at %d, want %d", matches[0].startAbs, want)
	}
}

func TestBrowserPassworderNestedCandidateWorkIsBounded(t *testing.T) {
	// Every close completes another valid JSON object containing all three
	// anchor keys. Without a shared byte budget, validating these nested
	// candidates costs object-sized work at every level. The leading vault is
	// still found; once the deliberately hostile nest consumes the allowance,
	// validation stops instead of doing quadratic work through the tail.
	const depth = 46
	prefix := strings.Repeat(`{"data":"","iv":"","salt":"","x":`, depth)
	hostile := prefix + `{}` + strings.Repeat(`}`, depth)
	raw := []byte(browserPassworderOldVault + hostile + browserPassworderOldVault)
	matches := findBrowserPassworderVaults(raw, 1200)
	if len(matches) != 1 {
		t.Fatalf("nested candidates produced matches %+v, want only the leading vault", matches)
	}
	if matches[0].startAbs != 1200 {
		t.Fatalf("leading match starts at %d, want 1200", matches[0].startAbs)
	}
}

func TestBrowserPassworderNoiseCorpus(t *testing.T) {
	rng := rand.New(rand.NewSource(99))
	noise := make([]byte, 1<<20)
	if _, err := rng.Read(noise); err != nil {
		t.Fatal(err)
	}
	if m := findBrowserPassworderVaults(noise, 0); len(m) != 0 {
		t.Fatalf("noise: %d matches, want 0", len(m))
	}
	for _, f := range []string{"../LICENSE", "../README.md", "../GOALS.md", "../main.go"} {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if m := findBrowserPassworderVaults(raw, 0); len(m) != 0 {
			t.Errorf("%s: %d matches, want 0", f, len(m))
		}
	}
}
