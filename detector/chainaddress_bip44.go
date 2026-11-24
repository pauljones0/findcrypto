package detector

import (
	"fmt"
	"math/big"
	"strings"
)

// bip44SecpProfile describes an external-chain, account-zero BIP44 profile.
// Coin types are the hardened SLIP-0044 values; address encoders receive the
// compressed SEC1 public key and never private material.
type bip44SecpProfile struct {
	chain    string
	profile  string
	coinType uint32
	address  func([]byte) (string, error)
}

var additionalBIP44RecoveryProfiles = []bip44SecpProfile{
	{chain: "litecoin", profile: RecoveryProfileLitecoin, coinType: 2, address: p2pkhAddressEncoder(48)},
	{chain: "dogecoin", profile: RecoveryProfileDogecoin, coinType: 3, address: p2pkhAddressEncoder(30)},
	{chain: "cosmos", profile: RecoveryProfileCosmos, coinType: 118, address: cosmosAccountAddress},
}

func bip44RecoveryProfile(name string) (bip44SecpProfile, bool) {
	for _, profile := range additionalBIP44RecoveryProfiles {
		if profile.profile == name {
			return profile, true
		}
	}
	return bip44SecpProfile{}, false
}

// deriveBIP44SecpRecoveryAddresses derives m/44'/coin'/0'/0/i. It is shared
// by UTXO-style P2PKH profiles and Cosmos SDK account addresses; those formats
// differ only in how HASH160(compressed-pubkey) is encoded.
func deriveBIP44SecpRecoveryAddresses(seed []byte, start uint32, count int, profile bip44SecpProfile) ([]RecoveryAddress, error) {
	priv, chain, err := bip32PrivateMaster(seed)
	if err != nil {
		return nil, fmt.Errorf("%s master key: %w", profile.chain, err)
	}
	defer func() {
		zeroBytes(priv)
		zeroBytes(chain)
	}()

	for depth, index := range []uint32{44 | 0x80000000, profile.coinType | 0x80000000, 0x80000000, 0} {
		childPriv, childChain, err := bip32PrivateChild(priv, chain, index)
		if err != nil {
			return nil, fmt.Errorf("%s derivation depth %d: %w", profile.chain, depth+1, err)
		}
		zeroBytes(priv)
		zeroBytes(chain)
		priv, chain = childPriv, childChain
	}

	out := make([]RecoveryAddress, 0, count)
	for i := 0; i < count; i++ {
		index := start + uint32(i)
		childPriv, childChain, err := bip32PrivateChild(priv, chain, index)
		if err != nil {
			return nil, fmt.Errorf("%s index %d: %w", profile.chain, index, err)
		}
		pub, pubErr := secpSerializeCompressed(secpMul(new(big.Int).SetBytes(childPriv), secpGenerator()))
		zeroBytes(childPriv)
		zeroBytes(childChain)
		if pubErr != nil {
			return nil, fmt.Errorf("%s index %d public key: %w", profile.chain, index, pubErr)
		}
		address, err := profile.address(pub)
		if err != nil {
			return nil, fmt.Errorf("%s index %d address: %w", profile.chain, index, err)
		}
		out = append(out, RecoveryAddress{
			Chain:   profile.chain,
			Profile: profile.profile,
			Path:    fmt.Sprintf("m/44'/%d'/0'/0/%d", profile.coinType, index),
			Index:   index,
			Address: address,
		})
	}
	return out, nil
}

func p2pkhAddressEncoder(version byte) func([]byte) (string, error) {
	return func(publicKey []byte) (string, error) {
		if len(publicKey) != 33 || (publicKey[0] != 2 && publicKey[0] != 3) {
			return "", fmt.Errorf("invalid compressed secp256k1 public key")
		}
		h := hash160(publicKey)
		return base58CheckEncode(append([]byte{version}, h[:]...)), nil
	}
}

// cosmosAccountAddress matches Cosmos SDK's legacy secp256k1 account address:
// Bech32("cosmos", RIPEMD160(SHA256(compressed SEC1 public key))).
func cosmosAccountAddress(publicKey []byte) (string, error) {
	if len(publicKey) != 33 || (publicKey[0] != 2 && publicKey[0] != 3) {
		return "", fmt.Errorf("invalid compressed secp256k1 public key")
	}
	h := hash160(publicKey)
	data, err := convertBits(h[:], 8, 5)
	if err != nil {
		return "", err
	}
	return bech32EncodeValues("cosmos", data)
}

// bech32EncodeValues encodes already-converted 5-bit values with the original
// Bech32 checksum constant. Cosmos account addresses are not SegWit programs,
// so they do not carry the witness-version value used by bech32SegwitEncode.
func bech32EncodeValues(hrp string, values []int) (string, error) {
	hrp = strings.ToLower(hrp)
	if len(hrp) < 1 || len(hrp)+1+len(values)+6 > 90 {
		return "", fmt.Errorf("invalid Bech32 length")
	}
	for i := 0; i < len(hrp); i++ {
		if hrp[i] < 33 || hrp[i] > 126 {
			return "", fmt.Errorf("invalid Bech32 HRP")
		}
	}
	for _, value := range values {
		if value < 0 || value > 31 {
			return "", fmt.Errorf("invalid Bech32 data value %d", value)
		}
	}
	pm := bech32Polymod(append(bech32HRPExpand(hrp), append(append([]int(nil), values...), 0, 0, 0, 0, 0, 0)...)) ^ 1
	var b strings.Builder
	b.Grow(len(hrp) + 1 + len(values) + 6)
	b.WriteString(hrp)
	b.WriteByte('1')
	for _, value := range values {
		b.WriteByte(bech32Charset[value])
	}
	for i := 0; i < 6; i++ {
		b.WriteByte(bech32Charset[(pm>>(5*(5-i)))&31])
	}
	return b.String(), nil
}
