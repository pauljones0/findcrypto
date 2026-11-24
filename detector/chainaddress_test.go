package detector

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"
)

// TestSeedToRecoveryAddressesKnownAnswers pins results from independent
// implementations: ethers 6.16.0 for EVM; bip39 3.1.0 plus ed25519-hd-key
// 1.3.0/Node's Ed25519 implementation for Solana; and @scure/bip32,
// @scure/bip39, and @scure/base 2.0.x for Litecoin, Dogecoin, and Cosmos.
// None of the oracles shares derivation or curve code with this package.
func TestSeedToRecoveryAddressesKnownAnswers(t *testing.T) {
	mnemonic := strings.Split("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", " ")
	addresses, err := SeedToRecoveryAddresses(mnemonic, 2)
	if err != nil {
		t.Fatal(err)
	}
	want := []RecoveryAddress{
		{Chain: "evm", Profile: RecoveryProfileEVM, Path: "m/44'/60'/0'/0/0", Index: 0, Address: "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"},
		{Chain: "evm", Profile: RecoveryProfileEVM, Path: "m/44'/60'/0'/0/1", Index: 1, Address: "0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0"},
		{Chain: "solana", Profile: RecoveryProfileSolana, Path: "m/44'/501'/0'/0'", Index: 0, Address: "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk"},
		{Chain: "solana", Profile: RecoveryProfileSolana, Path: "m/44'/501'/1'/0'", Index: 1, Address: "Hh8QwFUA6MtVu1qAoq12ucvFHNwCcVTV7hpWjeY1Hztb"},
		{Chain: "litecoin", Profile: RecoveryProfileLitecoin, Path: "m/44'/2'/0'/0/0", Index: 0, Address: "LUWPbpM43E2p7ZSh8cyTBEkvpHmr3cB8Ez"},
		{Chain: "litecoin", Profile: RecoveryProfileLitecoin, Path: "m/44'/2'/0'/0/1", Index: 1, Address: "Ldatw8ZjgMGNUo5HMN6RgCrjmh7q494Si3"},
		{Chain: "dogecoin", Profile: RecoveryProfileDogecoin, Path: "m/44'/3'/0'/0/0", Index: 0, Address: "DBus3bamQjgJULBJtYXpEzDWQRwF5iwxgC"},
		{Chain: "dogecoin", Profile: RecoveryProfileDogecoin, Path: "m/44'/3'/0'/0/1", Index: 1, Address: "DAcDAtJRztxBHyA6D6h8du1HguyTR43Mas"},
		{Chain: "cosmos", Profile: RecoveryProfileCosmos, Path: "m/44'/118'/0'/0/0", Index: 0, Address: "cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0auqdal4"},
		{Chain: "cosmos", Profile: RecoveryProfileCosmos, Path: "m/44'/118'/0'/0/1", Index: 1, Address: "cosmos1jrkmdcwgq94uaamx6zax2luewlhf7u4kucx3kz"},
	}
	if len(addresses) != len(want) {
		t.Fatalf("got %d addresses, want %d: %+v", len(addresses), len(want), addresses)
	}
	for i := range want {
		if addresses[i] != want[i] {
			t.Errorf("address[%d] = %+v, want %+v", i, addresses[i], want[i])
		}
	}
}

func TestSeedToRecoveryAddressesOptions(t *testing.T) {
	mnemonic := strings.Split("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", " ")
	addresses, err := SeedToRecoveryAddressesWithOptions(mnemonic, RecoveryOptions{
		Profiles: []string{RecoveryProfileEVM, RecoveryProfileEVM, RecoveryProfileCosmos},
		Start:    1,
		Count:    1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(addresses) != 2 || addresses[0].Index != 1 || addresses[0].Address != "0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0" || addresses[1].Address != "cosmos1jrkmdcwgq94uaamx6zax2luewlhf7u4kucx3kz" {
		t.Fatalf("selected addresses = %+v", addresses)
	}
	withPassphrase, err := SeedToRecoveryAddressesWithOptions(mnemonic, RecoveryOptions{
		Passphrase: []byte("TREZOR"), Profiles: []string{RecoveryProfileEVM}, Count: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(withPassphrase) != 1 || withPassphrase[0].Address == "0x9858EfFD232B4033E47d90003D41EC34EcaEda94" {
		t.Fatalf("passphrase did not change EVM identity: %+v", withPassphrase)
	}
	if _, err := SeedToRecoveryAddressesWithOptions(mnemonic, RecoveryOptions{Profiles: []string{"made-up"}, Count: 1}); err == nil {
		t.Fatal("unknown profile must fail")
	}
	if _, err := SeedToRecoveryAddressesWithOptions(mnemonic, RecoveryOptions{Start: RecoveryAddressMaxIndex - 1, Count: 2}); err == nil {
		t.Fatal("overflowing bounded index range must fail")
	}
}

// TestSLIP10Ed25519OfficialVector pins the full path from SLIP-0010 test
// vector 1. The vector is independent of Solana and verifies the primitive
// before the Solana path and address encoding are exercised above.
func TestSLIP10Ed25519OfficialVector(t *testing.T) {
	seed, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	if err != nil {
		t.Fatal(err)
	}
	path := []uint32{
		0x80000000,
		1 | 0x80000000,
		2 | 0x80000000,
		2 | 0x80000000,
		1000000000 | 0x80000000,
	}
	priv, chain, err := slip10Ed25519Derive(seed, path)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroBytes(priv)
	defer zeroBytes(chain)
	if got, want := hex.EncodeToString(priv), "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793"; got != want {
		t.Errorf("private = %s, want %s", got, want)
	}
	if got, want := hex.EncodeToString(chain), "68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230"; got != want {
		t.Errorf("chain = %s, want %s", got, want)
	}
	privateKey := ed25519.NewKeyFromSeed(priv)
	defer zeroBytes(privateKey)
	if got, want := hex.EncodeToString(privateKey[ed25519.SeedSize:]), "3c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a"; got != want {
		t.Errorf("public = %s, want %s", got, want)
	}
}

func TestSeedToRecoveryAddressesRefusesInvalidInputs(t *testing.T) {
	valid := strings.Split("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", " ")
	for _, count := range []int{-1, 0, RecoveryAddressMaxCount + 1} {
		if _, err := SeedToRecoveryAddresses(valid, count); err == nil {
			t.Errorf("count %d must fail", count)
		}
	}

	broken := append([]string(nil), valid...)
	broken[11] = "zoo"
	if _, err := SeedToRecoveryAddresses(broken, 1); err == nil {
		t.Error("checksum-broken mnemonic must fail")
	}
	unknown := append([]string(nil), valid...)
	unknown[3] = "notaword"
	if _, err := SeedToRecoveryAddresses(unknown, 1); err == nil {
		t.Error("unknown mnemonic word must fail")
	}
	if _, err := SeedToRecoveryAddresses(valid[:11], 1); err == nil {
		t.Error("wrong mnemonic length must fail")
	}
}

func TestSLIP10Ed25519RejectsNonHardenedChild(t *testing.T) {
	seed := make([]byte, 16)
	priv, chain, err := slip10Ed25519Derive(seed, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroBytes(priv)
	defer zeroBytes(chain)
	if _, _, err := slip10Ed25519Child(priv, chain, 0); err == nil {
		t.Fatal("non-hardened Ed25519 child must fail")
	}
}
