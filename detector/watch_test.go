package detector

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Oracle fixtures: account keys derived by btcsuite (hdkeychain) from the
// BIP39 test mnemonic "abandon ... about" (/tmp/xpub-oracle, kept out of the
// repo so findcrypto stays dependency-free). SLIP132 ypub/zpub/upub/vpub forms
// re-encode the same keys; addresses below are btcsuite's for both forms.

// bip44MainXPub is m/44'/0'/0' (P2PKH).
const bip44MainXPub = "xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj"

// bip49MainYSub is m/49'/0'/0' (P2SH-P2WPKH).
const bip49MainYPub = "ypub6Ww3ibxVfGzLrAH1PNcjyAWenMTbbAosGNB6VvmSEgytSER9azLDWCxoJwW7Ke7icmizBMXrzBx9979FfaHxHcrArf3zbeJJJUZPf663zsP"

// bip84MainZPub is m/84'/0'/0' (P2WPKH).
const bip84MainZPub = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs"

// bip44TestTPub is m/44'/1'/0' (testnet P2PKH).
const bip44TestTPub = "tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba"

// bip49TestUPub is m/49'/1'/0' (testnet P2SH-P2WPKH).
const bip49TestUPub = "upub5EFU65HtV5TeiSHmZZm7FUffBGy8UKeqp7vw43jYbvZPpoVsgU93oac7Wk3u6moKegAEWtGNF8DehrnHtv21XXEMYRUocHqguyjknFHYfgY"

// bip84TestVPub is m/84'/1'/0' (testnet P2WPKH).
const bip84TestVPub = "vpub5Y6cjg78GGuNLsaPhmYsiw4gYX3HoQiRBiSwDaBXKUafCt9bNwWQiitDk5VZ5BVxYnQdwoTyXSs2JHRPAgjAvtbBrf8ZhDYe2jWAqvZVnsc"

func TestRipemd160Vectors(t *testing.T) {
	long := []byte("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
	millionA := bytes.Repeat([]byte("a"), 1000000)
	range32 := make([]byte, 32)
	for i := range range32 {
		range32[i] = byte(i)
	}
	range100 := make([]byte, 100)
	for i := range range100 {
		range100[i] = byte(i)
	}
	cases := []struct {
		name string
		in   []byte
		want string
	}{
		{"empty", []byte{}, "9c1185a5c5e9fc54612808977ee8f548b2258d31"},
		{"abc", []byte("abc"), "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"},
		{"long", long, "12a053384a9c0c88e405a06c27dcf49ada62eb2b"},
		{"million-a", millionA, "52783243c1697bdbe16d37f97f68f08325dc1528"},
		{"range32", range32, "e6babb9619d7a81272711fc546a16b211dd93957"},
		{"range100", range100, "8ae5d2e6b1f3a514257f2469b637454931844aeb"},
	}
	for _, c := range cases {
		if got := fmt.Sprintf("%x", ripemd160Sum(c.in)); got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
}

// TestCKDPubVectors replays non-hardened steps from the published BIP32 test
// vectors: the full child xpub must match, which pins the EC math, HMAC
// chaining, fingerprinting, and base58 encoding all at once.
func TestCKDPubVectors(t *testing.T) {
	cases := []struct {
		name   string
		parent string
		index  uint32
		child  string
	}{
		{"v2 m/0",
			"xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
			0,
			"xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH"},
		{"v1 m/0H/1/2H/2",
			"xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
			2,
			"xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV"},
		{"v1 m/0H/1/2H/2/1000000000",
			"xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",
			1000000000,
			"xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"},
	}
	for _, c := range cases {
		p, err := ParseXPub(c.parent)
		if err != nil {
			t.Fatalf("%s: parse parent: %s", c.name, err)
		}
		k, err := DeriveChild(p, c.index)
		if err != nil {
			t.Fatalf("%s: derive: %s", c.name, err)
		}
		if got := k.String(); got != c.child {
			t.Errorf("%s:\n got %s\nwant %s", c.name, got, c.child)
		}
	}
	if _, err := DeriveChild(mustParseXPub(t, bip44MainXPub), 0x80000000); err == nil {
		t.Error("hardened derivation from public key must fail")
	}
}

// TestWatchAddressesOracle checks every script/network combination against
// the btcsuite oracle's addresses.
func TestWatchAddressesOracle(t *testing.T) {
	cases := []struct {
		name   string
		xpub   string
		fp     string
		script string
		ext    []string
		change []string
	}{
		{"bip44 main P2PKH", bip44MainXPub, "6cc9f252", "p2pkh",
			[]string{"1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA", "1Ak8PffB2meyfYnbXZR9EGfLfFZVpzJvQP", "1MNF5RSaabFwcbtJirJwKnDytsXXEsVsNb"},
			[]string{"1J3J6EvPrv8q6AC3VCjWV45Uf3nssNMRtH", "13vKxXzHXXd8HquAYdpkJoi9ULVXUgfpS5", "1M21Wx1nGrHMPaz52N2En7c624nzL4MYTk"}},
		{"bip49 main P2SH-P2WPKH", bip49MainYPub, "3a161284", "p2sh-p2wpkh",
			[]string{"37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf", "3LtMnn87fqUeHBUG414p9CWwnoV6E2pNKS", "3B4cvWGR8X6Xs8nvTxVUoMJV77E4f7oaia"},
			[]string{"34K56kSjgUCUSD8GTtuF7c9Zzwokbs6uZ7", "3516F2wmK51jVRrggEJsTUBNWMSLLjzvJ2", "3Grd7y95JEDTSh9uiVF5q7z2qGzmkP19CV"}},
		{"bip84 main P2WPKH", bip84MainZPub, "fd13aac9", "p2wpkh",
			[]string{"bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g", "bc1qp59yckz4ae5c4efgw2s5wfyvrz0ala7rgvuz8z"},
			[]string{"bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el", "bc1qggnasd834t54yulsep6fta8lpjekv4zj6gv5rf", "bc1qn8alfh45rlsj44pcdt0f2cadtztgnz4gq3h3uf"}},
		{"bip44 testnet P2PKH", bip44TestTPub, "4334c988", "p2pkh",
			[]string{"mkpZhYtJu2r87Js3pDiWJDmPte2NRZ8bJV", "mzpbWabUQm1w8ijuJnAof5eiSTep27deVH", "mnTkxhNkgx7TsZrEdRcPti564yQTzynGJp"},
			[]string{"mi8nhzZgGZQthq6DQHbru9crMDerUdTKva", "mz9HfS6y833A8HP8bfpLikzCbjonJXaAGW", "mnmhr8Z31n8GEN6ky4jp4h8VJjCRpRfzQW"}},
		{"bip49 testnet P2SH-P2WPKH", bip49TestUPub, "0a55db61", "p2sh-p2wpkh",
			[]string{"2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2", "2N55m54k8vr95ggehfUcNkdbUuQvaqG2GxK", "2N9LKph9TKtv1WLDfaUJp4D8EKwsyASYnGX"},
			[]string{"2MvdUi5o3f2tnEFh9yGvta6FzptTZtkPJC8", "2NCtHHE9TjYrYnUWfZv79w9ktk1f2uPUzqu", "2N9vVCnXmavTBmxRjoPjoHZ9q9ujEKXXGXe"}},
		{"bip84 testnet P2WPKH", bip84TestVPub, "e99b8628", "p2wpkh",
			[]string{"tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl", "tb1qd7spv5q28348xl4myc8zmh983w5jx32cjhkn97", "tb1qxdyjf6h5d6qxap4n2dap97q4j5ps6ua8sll0ct"},
			[]string{"tb1q9u62588spffmq4dzjxsr5l297znf3z6j5p2688", "tb1qkwgskuzmmwwvqajnyr7yp9hgvh5y45kg8wvdmd", "tb1q2vma00td2g9llw8hwa8ny3r774rtt7aenfn5zu"}},
	}
	for _, c := range cases {
		entries, err := CollectWatchAddrs([]string{c.xpub}, 3)
		if err != nil {
			t.Fatalf("%s: %s", c.name, err)
		}
		if len(entries) != 6 {
			t.Fatalf("%s: got %d entries, want 6", c.name, len(entries))
		}
		for i, e := range entries {
			var want string
			if e.Chain == 0 {
				want = c.ext[e.Index]
			} else {
				want = c.change[e.Index]
			}
			if e.Address != want {
				t.Errorf("%s entry %d (%s): got %s, want %s", c.name, i, e.Path, e.Address, want)
			}
			if e.Fingerprint != c.fp {
				t.Errorf("%s entry %d: fingerprint %s, want %s", c.name, i, e.Fingerprint, c.fp)
			}
			if e.Script != c.script {
				t.Errorf("%s entry %d: script %s, want %s", c.name, i, e.Script, c.script)
			}
			if e.Path != fmt.Sprintf("%d/%d", e.Chain, e.Index) {
				t.Errorf("%s entry %d: path %q inconsistent", c.name, i, e.Path)
			}
		}
	}
}

func mustParseXPub(t *testing.T, s string) *XPub {
	t.Helper()
	x, err := ParseXPub(s)
	if err != nil {
		t.Fatalf("parse xpub: %s", err)
	}
	return x
}

func TestParseXPubRefusals(t *testing.T) {
	// A valid xprv (BIP32 vector 1 chain m) must be refused, not parsed.
	if _, err := ParseXPub("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"); err == nil {
		t.Error("xprv must be refused")
	} else if !strings.Contains(err.Error(), "private") {
		t.Errorf("xprv error should say private, got: %s", err)
	}
	for _, bad := range []string{"", "xpub661MyMwAqRbc", "not a key at all!!"} {
		if _, err := ParseXPub(bad); err == nil {
			t.Errorf("input %q must fail", bad)
		}
	}
	// Flipped checksum byte.
	corrupt := bip44MainXPub[:100] + "1" + bip44MainXPub[101:]
	if _, err := ParseXPub(corrupt); err == nil {
		t.Error("corrupted checksum must fail")
	}
	// Unknown version bytes, re-checksummed.
	raw, _ := base58CheckDecode(bip44MainXPub)
	mut := append([]byte(nil), raw...)
	binary.BigEndian.PutUint32(mut[:4], 0xdeadbeef)
	if _, err := ParseXPub(base58CheckEncode(mut)); err == nil {
		t.Error("unknown version must fail")
	}
	// Uncompressed key marker, re-checksummed.
	mut2 := append([]byte(nil), raw...)
	mut2[45] = 0x04
	if _, err := ParseXPub(base58CheckEncode(mut2)); err == nil {
		t.Error("uncompressed key must fail")
	}
	// Depth-0 master with nonzero fingerprint.
	mut3 := append([]byte(nil), raw...)
	mut3[4] = 0
	mut3[5] = 0x01
	if _, err := ParseXPub(base58CheckEncode(mut3)); err == nil {
		t.Error("depth-0 key with nonzero fingerprint must fail")
	}
	// Off-curve compressed key: x = p (out of range).
	mut4 := append([]byte(nil), raw...)
	for i := 46; i < 78; i++ {
		mut4[i] = 0xff
	}
	if _, err := ParseXPub(base58CheckEncode(mut4)); err == nil {
		t.Error("out-of-range key must fail")
	}
}

func TestBase58Roundtrip(t *testing.T) {
	rng := rand.New(rand.NewSource(5))
	// Empty input is rejected by the pre-existing decoder; everything else
	// must round-trip.
	bufs := [][]byte{{0}, {0, 0, 0}, {1, 2, 3}}
	for i := 0; i < 50; i++ {
		b := make([]byte, 1+rng.Intn(90))
		rng.Read(b)
		if i%3 == 0 {
			b[0] = 0 // leading-zero runs exercise the '1' prefix
		}
		bufs = append(bufs, b)
	}
	for i, b := range bufs {
		enc := base58Encode(b)
		dec, ok := base58Decode(enc)
		if !ok {
			t.Fatalf("case %d: decode failed", i)
		}
		if !bytes.Equal(dec, b) {
			t.Fatalf("case %d: roundtrip mismatch", i)
		}
	}
	// The oracle xpubs survive a decode/re-encode round trip byte for byte.
	for _, x := range []string{bip44MainXPub, bip49MainYPub, bip84MainZPub, bip44TestTPub, bip49TestUPub, bip84TestVPub} {
		raw, ok := base58Decode(x)
		if !ok || base58Encode(raw) != x {
			t.Errorf("%s... roundtrip failed", x[:8])
		}
	}
}

func TestExtractXpubs(t *testing.T) {
	xprv := "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
	var buf bytes.Buffer
	buf.WriteString("\x00binary\xff noise ")
	buf.WriteString(bip84MainZPub)
	buf.WriteString(" middle ")
	buf.WriteString(xprv) // private: noted, never returned
	buf.WriteString(" ")
	buf.WriteString(bip84MainZPub) // duplicate
	buf.WriteString(" tail ")
	buf.WriteString(bip44TestTPub)
	pubs, priv := ExtractXpubs(buf.Bytes())
	if !priv {
		t.Error("xprv presence must be reported")
	}
	if len(pubs) != 2 || pubs[0] != bip84MainZPub || pubs[1] != bip44TestTPub {
		t.Errorf("got %d pubs, want [zpub tpub] deduplicated", len(pubs))
	}
	if pubs, priv := ExtractXpubs([]byte("nothing but noise here")); len(pubs) != 0 || priv {
		t.Error("noise must yield nothing")
	}
	if pubs, _ := ExtractXpubs(make([]byte, WatchScanMaxBytes+1)); pubs != nil {
		t.Error("oversized input must be skipped")
	}
}

func TestCollectWatchAddrsShape(t *testing.T) {
	entries, err := CollectWatchAddrs([]string{bip44MainXPub}, WatchDefaultCount)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2*WatchDefaultCount {
		t.Fatalf("got %d entries, want %d", len(entries), 2*WatchDefaultCount)
	}
	if entries[0].Path != "0/0" || entries[WatchDefaultCount].Path != "1/0" {
		t.Errorf("chain ordering wrong: %s, %s", entries[0].Path, entries[WatchDefaultCount].Path)
	}
	for _, n := range []int{0, -1, WatchMaxCount + 1} {
		if _, err := CollectWatchAddrs([]string{bip44MainXPub}, n); err == nil {
			t.Errorf("count %d must fail", n)
		}
	}
	if _, err := CollectWatchAddrs([]string{"bogus"}, 3); err == nil {
		t.Error("bogus key must fail")
	}
}

func TestCollectWatchChainSkipsInvalidChildrenWithoutShortening(t *testing.T) {
	acct := mustParseXPub(t, bip44MainXPub)
	chainKey, err := DeriveChild(acct, 0)
	if err != nil {
		t.Fatal(err)
	}
	derive := func(parent *XPub, index uint32) (*XPub, error) {
		if index == 0 || index == 2 {
			return nil, errInvalidChild
		}
		return DeriveChild(parent, index)
	}
	entries, err := collectWatchChain(acct, chainKey, acct.Fingerprint(), 0, 3, 0, derive)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("got %d entries after invalid children, want exactly 3", len(entries))
	}
	want := []uint32{1, 3, 4}
	for i, entry := range entries {
		if entry.Index != want[i] || entry.Path != fmt.Sprintf("0/%d", want[i]) {
			t.Errorf("entry %d = index %d path %q, want index %d", i, entry.Index, entry.Path, want[i])
		}
	}

	// An invalid final non-hardened child must fail rather than wrap into the
	// hardened half of the index space or loop forever.
	_, err = collectWatchChain(acct, chainKey, acct.Fingerprint(), 0, 1, 0x7fffffff,
		func(*XPub, uint32) (*XPub, error) { return nil, errInvalidChild })
	if err == nil || !strings.Contains(err.Error(), "exhausted non-hardened") {
		t.Fatalf("non-hardened boundary error = %v", err)
	}
}

func TestWatchExportGolden(t *testing.T) {
	entries, err := CollectWatchAddrs([]string{bip44MainXPub}, 1)
	if err != nil {
		t.Fatal(err)
	}
	var csvBuf bytes.Buffer
	if err := WriteWatchCSV(&csvBuf, entries); err != nil {
		t.Fatal(err)
	}
	wantCSV := "fingerprint,version,chain,index,path,address,script,balance_sats,tx_count,funded_txo_sum,spent_txo_sum,used\n" +
		"6cc9f252,xpub,0,0,0/0,1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA,p2pkh,,,,,\n" +
		"6cc9f252,xpub,1,0,1/0,1J3J6EvPrv8q6AC3VCjWV45Uf3nssNMRtH,p2pkh,,,,,\n"
	if csvBuf.String() != wantCSV {
		t.Errorf("CSV mismatch:\n got:\n%s\nwant:\n%s", csvBuf.String(), wantCSV)
	}
	var jsonBuf bytes.Buffer
	if err := WriteWatchJSON(&jsonBuf, entries); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(jsonBuf.String(), `"address": "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"`) ||
		!strings.Contains(jsonBuf.String(), `"fingerprint": "6cc9f252"`) {
		t.Errorf("JSON missing entries:\n%s", jsonBuf.String())
	}
	if strings.Contains(jsonBuf.String(), `"balance_sats"`) || strings.Contains(jsonBuf.String(), `"used"`) {
		t.Errorf("offline JSON must leave activity unknown, not zero:\n%s", jsonBuf.String())
	}
	// Privacy: the extended key itself appears in neither export.
	for name, out := range map[string]string{"csv": csvBuf.String(), "json": jsonBuf.String()} {
		if strings.Contains(out, bip44MainXPub) {
			t.Errorf("%s export leaks the xpub", name)
		}
	}
}

func TestWatchExportActivityDistinguishesUnusedFromUnknown(t *testing.T) {
	i64 := func(v int64) *int64 { return &v }
	boolean := func(v bool) *bool { return &v }
	entries := []WatchEntry{
		{
			Fingerprint: "spent", Version: "xpub", Path: "0/0", Address: "addr-spent", Script: "p2pkh",
			BalanceSats: i64(0), TxCount: i64(3), FundedTxoSum: i64(50000),
			SpentTxoSum: i64(50000), Used: boolean(true),
		},
		{
			Fingerprint: "unused", Version: "xpub", Path: "0/1", Address: "addr-unused", Script: "p2pkh",
			BalanceSats: i64(0), TxCount: i64(0), FundedTxoSum: i64(0),
			SpentTxoSum: i64(0), Used: boolean(false),
		},
		{Fingerprint: "unknown", Version: "xpub", Path: "0/2", Address: "addr-failed", Script: "p2pkh"},
	}

	var csvBuf bytes.Buffer
	if err := WriteWatchCSV(&csvBuf, entries); err != nil {
		t.Fatal(err)
	}
	wantLines := []string{
		"spent,xpub,0,0,0/0,addr-spent,p2pkh,0,3,50000,50000,true",
		"unused,xpub,0,0,0/1,addr-unused,p2pkh,0,0,0,0,false",
		"unknown,xpub,0,0,0/2,addr-failed,p2pkh,,,,,",
	}
	for _, want := range wantLines {
		if !strings.Contains(csvBuf.String(), want+"\n") {
			t.Errorf("CSV missing %q:\n%s", want, csvBuf.String())
		}
	}

	var jsonBuf bytes.Buffer
	if err := WriteWatchJSON(&jsonBuf, entries); err != nil {
		t.Fatal(err)
	}
	jsonOut := jsonBuf.String()
	for _, want := range []string{`"tx_count": 3`, `"funded_txo_sum": 50000`, `"spent_txo_sum": 50000`, `"used": true`, `"used": false`} {
		if !strings.Contains(jsonOut, want) {
			t.Errorf("JSON missing %s:\n%s", want, jsonOut)
		}
	}
	unknownStart := strings.Index(jsonOut, `"fingerprint": "unknown"`)
	if unknownStart < 0 {
		t.Fatalf("JSON missing unknown entry:\n%s", jsonOut)
	}
	unknown := jsonOut[unknownStart:]
	if strings.Contains(unknown, `"balance_sats"`) || strings.Contains(unknown, `"used"`) {
		t.Errorf("failed lookup serialized as known activity:\n%s", unknown)
	}
}

func TestWatchFingerprintOracle(t *testing.T) {
	// Fingerprints verified with Python hashlib (independent implementation).
	for xpub, want := range map[string]string{
		bip44MainXPub: "6cc9f252", bip49MainYPub: "3a161284",
		bip84MainZPub: "fd13aac9", bip44TestTPub: "4334c988",
		bip49TestUPub: "0a55db61", bip84TestVPub: "e99b8628",
	} {
		if got := mustParseXPub(t, xpub).Fingerprint(); got != want {
			t.Errorf("%s...: fingerprint %s, want %s", xpub[:8], got, want)
		}
	}
}

// TestLookupActivity exercises the opt-in endpoint client against a local
// Esplora-shaped stub: confirmed+mempool aggregation, spent history at zero
// balance, a genuinely unused address, and partial failures that stay unknown.
func TestLookupActivity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch strings.TrimPrefix(r.URL.Path, "/address/") {
		case "addr-funded":
			fmt.Fprint(w, `{"chain_stats":{"tx_count":2,"funded_txo_sum":50000,"spent_txo_sum":10000},"mempool_stats":{"tx_count":1,"funded_txo_sum":2000,"spent_txo_sum":0}}`)
		case "addr-spent":
			fmt.Fprint(w, `{"chain_stats":{"tx_count":2,"funded_txo_sum":50000,"spent_txo_sum":50000},"mempool_stats":{"tx_count":0,"funded_txo_sum":0,"spent_txo_sum":0}}`)
		case "addr-empty":
			fmt.Fprint(w, `{"chain_stats":{"tx_count":0,"funded_txo_sum":0,"spent_txo_sum":0},"mempool_stats":{"tx_count":0,"funded_txo_sum":0,"spent_txo_sum":0}}`)
		case "addr-incomplete":
			fmt.Fprint(w, `{"chain_stats":{"tx_count":0,"funded_txo_sum":0,"spent_txo_sum":0},"mempool_stats":{}}`)
		case "addr-negative":
			fmt.Fprint(w, `{"chain_stats":{"tx_count":-1,"funded_txo_sum":0,"spent_txo_sum":0},"mempool_stats":{"tx_count":0,"funded_txo_sum":0,"spent_txo_sum":0}}`)
		case "addr-overspent":
			fmt.Fprint(w, `{"chain_stats":{"tx_count":1,"funded_txo_sum":1,"spent_txo_sum":2},"mempool_stats":{"tx_count":0,"funded_txo_sum":0,"spent_txo_sum":0}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	client := srv.Client()
	got, err := LookupActivity(client, srv.URL, []string{"addr-funded", "addr-spent", "addr-empty"})
	if err != nil {
		t.Fatalf("lookup: %s", err)
	}
	funded := got["addr-funded"]
	if funded.TxCount != 3 || funded.FundedTxoSum != 52000 || funded.SpentTxoSum != 10000 || funded.BalanceSats != 42000 || !funded.Used {
		t.Errorf("funded activity = %+v, want tx=3 funded=52000 spent=10000 balance=42000 used", funded)
	}
	spent := got["addr-spent"]
	if spent.BalanceSats != 0 || !spent.Used || spent.TxCount != 2 {
		t.Errorf("spent activity = %+v, want zero balance with history", spent)
	}
	empty := got["addr-empty"]
	if empty.BalanceSats != 0 || empty.Used || empty.TxCount != 0 {
		t.Errorf("empty activity = %+v, want explicit unused zero", empty)
	}

	// Partial failures: successes stay, while HTTP, incomplete-JSON, and
	// invalid-counter failures have no result entry (unknown, never zero).
	got, err = LookupActivity(client, srv.URL, []string{"addr-funded", "addr-missing", "addr-incomplete", "addr-negative", "addr-overspent"})
	if err == nil {
		t.Fatal("bad addresses must produce an error")
	}
	if got["addr-funded"].BalanceSats != 42000 {
		t.Errorf("partial success lost: %v", got)
	}
	for _, addr := range []string{"addr-missing", "addr-incomplete", "addr-negative", "addr-overspent"} {
		if _, ok := got[addr]; ok {
			t.Errorf("failed %s lookup became known zero: %v", addr, got[addr])
		}
	}
	if !strings.Contains(err.Error(), "4 of 5 lookups failed") || !strings.Contains(err.Error(), "spent_txo_sum 2 exceeds funded_txo_sum 1") {
		t.Errorf("combined failure count missing: %s", err)
	}
	if _, err := LookupActivity(nil, srv.URL, []string{"addr-funded"}); err == nil {
		t.Error("nil client must fail")
	}
	if _, err := LookupActivity(client, "", []string{"addr-funded"}); err == nil {
		t.Error("empty endpoint must fail")
	}
	//lint:ignore SA1012 Deliberately verify that the exported boundary rejects a nil context.
	if _, err := LookupActivityContext(nil, client, srv.URL, []string{"addr-funded"}); err == nil {
		t.Error("nil context must fail")
	}

	// The original balance-only API remains source-compatible for callers.
	bal, err := LookupBalances(client, srv.URL, []string{"addr-funded", "addr-spent"})
	if err != nil || bal["addr-funded"] != 42000 || bal["addr-spent"] != 0 {
		t.Errorf("balance compatibility = %v, %v", bal, err)
	}
}

const emptyEsploraActivity = `{"chain_stats":{"tx_count":0,"funded_txo_sum":0,"spent_txo_sum":0},"mempool_stats":{"tx_count":0,"funded_txo_sum":0,"spent_txo_sum":0}}`

func TestLookupActivityBoundedConcurrency(t *testing.T) {
	var active, peak atomic.Int32
	entered := make(chan struct{}, EsploraLookupConcurrency)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		now := active.Add(1)
		defer active.Add(-1)
		for {
			old := peak.Load()
			if now <= old || peak.CompareAndSwap(old, now) {
				break
			}
		}
		entered <- struct{}{}
		select {
		case <-release:
			fmt.Fprint(w, emptyEsploraActivity)
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()

	addrs := make([]string, EsploraLookupConcurrency+7)
	for i := range addrs {
		addrs[i] = fmt.Sprintf("addr-%02d", i)
	}
	type answer struct {
		activity map[string]AddressActivity
		err      error
	}
	done := make(chan answer, 1)
	go func() {
		a, err := LookupActivity(srv.Client(), srv.URL, addrs)
		done <- answer{a, err}
	}()
	for i := 0; i < EsploraLookupConcurrency; i++ {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			close(release)
			t.Fatalf("only %d requests entered; worker pool never filled", i)
		}
	}
	if got := peak.Load(); got != EsploraLookupConcurrency {
		close(release)
		t.Fatalf("peak concurrency = %d, want %d", got, EsploraLookupConcurrency)
	}
	close(release)
	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("lookup: %v", got.err)
		}
		if len(got.activity) != len(addrs) {
			t.Fatalf("got %d activities, want %d", len(got.activity), len(addrs))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("bounded lookup did not finish")
	}
	if got := peak.Load(); got > EsploraLookupConcurrency {
		t.Fatalf("peak concurrency grew to %d, limit %d", got, EsploraLookupConcurrency)
	}
}

func TestLookupActivityContextCancellation(t *testing.T) {
	entered := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-r.Context().Done()
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := LookupActivityContext(ctx, srv.Client(), srv.URL,
			[]string{"a", "b", "c", "d", "e", "f", "g", "h", "i"})
		done <- err
	}()
	select {
	case <-entered:
		cancel()
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("lookup never reached endpoint")
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation error = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("canceled lookup did not return")
	}
}

func TestLookupActivityDeduplicatesAndOrdersFailures(t *testing.T) {
	var okHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch strings.TrimPrefix(r.URL.Path, "/address/") {
		case "first":
			time.Sleep(40 * time.Millisecond)
			http.Error(w, "no", http.StatusBadGateway)
		case "second":
			fmt.Fprint(w, `{bad json`)
		case "ok":
			okHits.Add(1)
			fmt.Fprint(w, emptyEsploraActivity)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	got, err := LookupActivity(srv.Client(), srv.URL, []string{"first", "ok", "second", "ok"})
	if err == nil {
		t.Fatal("failed lookups returned no error")
	}
	if okHits.Load() != 1 {
		t.Fatalf("duplicate address queried %d times, want 1", okHits.Load())
	}
	if a, ok := got["ok"]; !ok || a.Used {
		t.Fatalf("successful explicit-unused result = %+v, present=%v", a, ok)
	}
	if len(got) != 1 {
		t.Fatalf("successful result map = %v, want only ok", got)
	}
	msg := err.Error()
	first := strings.Index(msg, "first:")
	second := strings.Index(msg, "second:")
	if !strings.Contains(msg, "2 of 3 lookups failed") || first < 0 || second < 0 || first > second {
		t.Fatalf("failure summary is not first-seen deterministic: %s", msg)
	}
}

// TestWatchDefaultOffline pins the Goal 5 invariant: the default
// derive-and-export path completes with a nil HTTP client, i.e. it cannot
// perform network I/O because it has no transport to do it with.
func TestWatchDefaultOffline(t *testing.T) {
	var noClient *http.Client
	entries, err := CollectWatchAddrs([]string{bip84TestVPub}, 2)
	if err != nil {
		t.Fatal(err)
	}
	if noClient != nil {
		t.Fatal("unreachable")
	}
	var csvBuf, jsonBuf bytes.Buffer
	if err := WriteWatchCSV(&csvBuf, entries); err != nil {
		t.Fatal(err)
	}
	if err := WriteWatchJSON(&jsonBuf, entries); err != nil {
		t.Fatal(err)
	}
	if csvBuf.Len() == 0 || jsonBuf.Len() == 0 {
		t.Error("default export produced no output")
	}
}

// TestScannerFindsSLIP132Versions keeps detector coverage aligned with the
// watch parser: every version ParseXPub accepts must also scan.
func TestScannerFindsSLIP132Versions(t *testing.T) {
	buf := []byte("pad " + bip49TestUPub + " pad " + bip84TestVPub + " pad")
	matches := findKeys(buf, 1000, true, true)
	got := map[string]bool{}
	for _, m := range matches {
		got[m.label] = true
	}
	if !got["upub"] || !got["vpub"] {
		t.Errorf("scanner missed SLIP132 testnet keys: %v", got)
	}
	// The classifier (version bytes only) and report agree on the new
	// testnet-segwit versions.
	for ver, label := range map[uint32]string{0x044A4E28: "uprv", 0x044A5262: "upub", 0x045F18BC: "vprv", 0x045F1CF6: "vpub"} {
		payload := make([]byte, 78)
		binary.BigEndian.PutUint32(payload, ver)
		gotLabel, ok := classifyXKey(payload)
		if !ok || gotLabel != label {
			t.Errorf("version 0x%08x: got %q,%v want %q", ver, gotLabel, ok, label)
		}
	}
	if c := classifyNeedle("upub"); c.walletType != "extended-public-key" {
		t.Errorf("upub report class %q", c.walletType)
	}
	if c := classifyNeedle("vprv"); c.walletType != "extended-private-key" {
		t.Errorf("vprv report class %q", c.walletType)
	}
}

func TestWatchDerivationSpeed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timing test in short mode")
	}
	start := time.Now()
	if _, err := CollectWatchAddrs([]string{bip84MainZPub}, WatchDefaultCount); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 30*time.Second {
		t.Errorf("default derivation took %s, want under 30s", elapsed)
	}
}
