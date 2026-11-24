package detector

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"golang.org/x/crypto/sha3"
)

// RecoveryAddress is one public address derived from a recovered mnemonic.
// Address derivation is local and offline; private keys and the BIP39 seed are
// never returned.
type RecoveryAddress struct {
	Chain   string `json:"chain"`
	Profile string `json:"profile"`
	Path    string `json:"path"`
	Index   uint32 `json:"index"`
	Address string `json:"address"`
}

// RecoveryAddressMaxCount bounds CPU and memory for private-path derivation.
// The in-tree affine secp256k1 implementation prioritizes auditability over
// throughput; 100 already exceeds the usual 20-address discovery gap.
const (
	RecoveryAddressMaxCount = 100
	// RecoveryAddressMaxIndex bounds configurable path discovery well below
	// the hardened boundary while still covering unusually large wallets.
	RecoveryAddressMaxIndex = 10000
)

const (
	RecoveryProfileEVM      = "evm-standard"
	RecoveryProfileSolana   = "solana-standard"
	RecoveryProfileLitecoin = "litecoin-bip44"
	RecoveryProfileDogecoin = "dogecoin-bip44"
	RecoveryProfileCosmos   = "cosmos-hub"
)

var recoveryProfileOrder = []string{
	RecoveryProfileEVM,
	RecoveryProfileSolana,
	RecoveryProfileLitecoin,
	RecoveryProfileDogecoin,
	RecoveryProfileCosmos,
}

// RecoveryOptions selects named, vector-backed derivation presets. Start and
// Count refer to each profile's varying address/account slot. Arbitrary path
// strings are intentionally unsupported.
type RecoveryOptions struct {
	Passphrase []byte
	Profiles   []string
	Start      uint32
	Count      int
}

// SupportedRecoveryProfiles returns stable profile names in default order.
func SupportedRecoveryProfiles() []string {
	return append([]string(nil), recoveryProfileOrder...)
}

// SeedToRecoveryAddresses derives count public addresses for each supported
// recovery profile. EVM represents every chain that uses the Ethereum address
// scheme (Ethereum, Polygon, Base, Arbitrum, Optimism, BNB Chain, Avalanche
// C-Chain, and others); an address alone cannot distinguish those networks.
// Solana uses SLIP-0010 Ed25519 derivation. Litecoin, Dogecoin, and Cosmos use
// their registered BIP44 coin types with account zero and the external chain.
//
// Paths:
//   - EVM: m/44'/60'/0'/0/index
//   - Solana: m/44'/501'/index'/0'
//   - Litecoin: m/44'/2'/0'/0/index
//   - Dogecoin: m/44'/3'/0'/0/index
//   - Cosmos Hub: m/44'/118'/0'/0/index
//
// The mnemonic must be checksum-valid BIP39. This compatibility entry point
// uses the empty BIP39 passphrase; use SeedToRecoveryAddressesWithOptions for
// a protected passphrase, profile selection, or a nonzero start index. No
// network calls are made.
func SeedToRecoveryAddresses(mnemonic []string, count int) ([]RecoveryAddress, error) {
	return SeedToRecoveryAddressesWithOptions(mnemonic, RecoveryOptions{Count: count})
}

// SeedToRecoveryAddressesWithOptions derives selected public identity
// profiles locally. Empty Profiles selects every supported profile. The
// caller retains ownership of Passphrase; it is NFKD-normalized internally.
func SeedToRecoveryAddressesWithOptions(mnemonic []string, opts RecoveryOptions) ([]RecoveryAddress, error) {
	if opts.Count < 1 || opts.Count > RecoveryAddressMaxCount {
		return nil, fmt.Errorf("count %d out of range 1-%d", opts.Count, RecoveryAddressMaxCount)
	}
	end := uint64(opts.Start) + uint64(opts.Count)
	if opts.Start >= RecoveryAddressMaxIndex || end > RecoveryAddressMaxIndex {
		return nil, fmt.Errorf("index range %d..%d exceeds maximum %d", opts.Start, end-1, RecoveryAddressMaxIndex-1)
	}
	profiles, err := validateRecoveryProfiles(opts.Profiles)
	if err != nil {
		return nil, err
	}
	seed, err := mnemonicToSeed(mnemonic, opts.Passphrase)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(seed)

	out := make([]RecoveryAddress, 0, len(profiles)*opts.Count)
	for _, name := range profiles {
		var addresses []RecoveryAddress
		switch name {
		case RecoveryProfileEVM:
			addresses, err = deriveEVMRecoveryAddresses(seed, opts.Start, opts.Count)
		case RecoveryProfileSolana:
			addresses, err = deriveSolanaRecoveryAddresses(seed, opts.Start, opts.Count)
		default:
			profile, ok := bip44RecoveryProfile(name)
			if !ok {
				return nil, fmt.Errorf("internal error: missing recovery profile %q", name)
			}
			addresses, err = deriveBIP44SecpRecoveryAddresses(seed, opts.Start, opts.Count, profile)
		}
		if err != nil {
			return nil, err
		}
		out = append(out, addresses...)
	}
	return out, nil
}

func validateRecoveryProfiles(requested []string) ([]string, error) {
	if len(requested) == 0 {
		return SupportedRecoveryProfiles(), nil
	}
	valid := make(map[string]bool, len(recoveryProfileOrder))
	for _, name := range recoveryProfileOrder {
		valid[name] = true
	}
	seen := make(map[string]bool, len(requested))
	out := make([]string, 0, len(requested))
	for _, raw := range requested {
		name := strings.ToLower(strings.TrimSpace(raw))
		if !valid[name] {
			return nil, fmt.Errorf("unknown recovery profile %q (want %s)", raw, strings.Join(recoveryProfileOrder, ","))
		}
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	return out, nil
}

func deriveEVMRecoveryAddresses(seed []byte, start uint32, count int) ([]RecoveryAddress, error) {
	priv, chain, err := bip32PrivateMaster(seed)
	if err != nil {
		return nil, fmt.Errorf("evm master key: %w", err)
	}
	// Use a closure because priv/chain are replaced while walking the fixed
	// prefix; defer arguments would otherwise retain only the already-wiped
	// master slices and leave the final account node live.
	defer func() {
		zeroBytes(priv)
		zeroBytes(chain)
	}()

	for depth, index := range []uint32{44 | 0x80000000, 60 | 0x80000000, 0x80000000, 0} {
		childPriv, childChain, err := bip32PrivateChild(priv, chain, index)
		if err != nil {
			return nil, fmt.Errorf("evm derivation depth %d: %w", depth+1, err)
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
			return nil, fmt.Errorf("evm index %d: %w", index, err)
		}
		address, err := evmAddress(childPriv)
		zeroBytes(childPriv)
		zeroBytes(childChain)
		if err != nil {
			return nil, fmt.Errorf("evm index %d: %w", index, err)
		}
		out = append(out, RecoveryAddress{
			Chain:   "evm",
			Profile: RecoveryProfileEVM,
			Path:    fmt.Sprintf("m/44'/60'/0'/0/%d", index),
			Index:   index,
			Address: address,
		})
	}
	return out, nil
}

func deriveSolanaRecoveryAddresses(seed []byte, start uint32, count int) ([]RecoveryAddress, error) {
	basePriv, baseChain, err := slip10Ed25519Derive(seed, []uint32{44 | 0x80000000, 501 | 0x80000000})
	if err != nil {
		return nil, fmt.Errorf("solana base path: %w", err)
	}
	defer zeroBytes(basePriv)
	defer zeroBytes(baseChain)

	out := make([]RecoveryAddress, 0, count)
	for i := 0; i < count; i++ {
		index := start + uint32(i)
		accountPriv, accountChain, err := slip10Ed25519Child(basePriv, baseChain, index|0x80000000)
		if err != nil {
			return nil, fmt.Errorf("solana account %d: %w", index, err)
		}
		leafPriv, leafChain, err := slip10Ed25519Child(accountPriv, accountChain, 0x80000000)
		zeroBytes(accountPriv)
		zeroBytes(accountChain)
		if err != nil {
			return nil, fmt.Errorf("solana account %d change: %w", index, err)
		}
		privateKey := ed25519.NewKeyFromSeed(leafPriv)
		publicKey := privateKey[ed25519.SeedSize:]
		address := base58Encode(publicKey)
		zeroBytes(privateKey)
		zeroBytes(leafPriv)
		zeroBytes(leafChain)
		out = append(out, RecoveryAddress{
			Chain:   "solana",
			Profile: RecoveryProfileSolana,
			Path:    fmt.Sprintf("m/44'/501'/%d'/0'", index),
			Index:   index,
			Address: address,
		})
	}
	return out, nil
}

// bip32PrivateMaster derives the BIP32 secp256k1 master private node.
func bip32PrivateMaster(seed []byte) ([]byte, []byte, error) {
	mac := hmac.New(sha512.New, []byte("Bitcoin seed"))
	mac.Write(seed)
	master := mac.Sum(nil)
	defer zeroBytes(master)
	if !validPrivBytes(master[:32]) {
		return nil, nil, errors.New("derived an invalid master key (astronomically rare)")
	}
	return append([]byte(nil), master[:32]...), append([]byte(nil), master[32:]...), nil
}

// bip32PrivateChild applies BIP32 CKDpriv. Fixed recovery paths fail loudly on
// the astronomically rare invalid child instead of silently changing a path.
func bip32PrivateChild(parentPriv, parentChain []byte, index uint32) ([]byte, []byte, error) {
	if len(parentPriv) != 32 || len(parentChain) != 32 || !validPrivBytes(parentPriv) {
		return nil, nil, errors.New("invalid parent private node")
	}
	var data [37]byte
	defer zeroBytes(data[:])
	if index&0x80000000 != 0 {
		copy(data[1:33], parentPriv)
	} else {
		pub, err := secpSerializeCompressed(secpMul(new(big.Int).SetBytes(parentPriv), secpGenerator()))
		if err != nil {
			return nil, nil, err
		}
		copy(data[:33], pub)
	}
	binary.BigEndian.PutUint32(data[33:], index)
	mac := hmac.New(sha512.New, parentChain)
	mac.Write(data[:])
	I := mac.Sum(nil)
	defer zeroBytes(I)
	il := new(big.Int).SetBytes(I[:32])
	if il.Cmp(secpN) >= 0 {
		return nil, nil, errors.New("invalid child scalar (astronomically rare)")
	}
	child := new(big.Int).Add(il, new(big.Int).SetBytes(parentPriv))
	child.Mod(child, secpN)
	if child.Sign() == 0 {
		return nil, nil, errors.New("invalid zero child key (astronomically rare)")
	}
	return leftPad32(child.Bytes()), append([]byte(nil), I[32:]...), nil
}

func evmAddress(privateKey []byte) (string, error) {
	if !validPrivBytes(privateKey) {
		return "", errors.New("invalid EVM private key")
	}
	point := secpMul(new(big.Int).SetBytes(privateKey), secpGenerator())
	if point.isInfinity() {
		return "", errors.New("EVM public key is at infinity")
	}
	publicKey := make([]byte, 64)
	x, y := point.x.Bytes(), point.y.Bytes()
	copy(publicKey[32-len(x):32], x)
	copy(publicKey[64-len(y):], y)
	hash := legacyKeccak256(publicKey)
	return eip55Address(hash[12:]), nil
}

func legacyKeccak256(data []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	_, _ = h.Write(data)
	return h.Sum(nil)
}

func eip55Address(raw []byte) string {
	lower := []byte(hex.EncodeToString(raw))
	hash := legacyKeccak256(lower)
	for i, c := range lower {
		if c < 'a' || c > 'f' {
			continue
		}
		nibble := hash[i/2] >> 4
		if i%2 == 1 {
			nibble = hash[i/2] & 0x0f
		}
		if nibble >= 8 {
			lower[i] = c - ('a' - 'A')
		}
	}
	return "0x" + string(lower)
}

// slip10Ed25519Derive derives a hardened-only SLIP-0010 Ed25519 node.
func slip10Ed25519Derive(seed []byte, path []uint32) ([]byte, []byte, error) {
	mac := hmac.New(sha512.New, []byte("ed25519 seed"))
	mac.Write(seed)
	master := mac.Sum(nil)
	priv := append([]byte(nil), master[:32]...)
	chain := append([]byte(nil), master[32:]...)
	zeroBytes(master)
	for _, index := range path {
		childPriv, childChain, err := slip10Ed25519Child(priv, chain, index)
		zeroBytes(priv)
		zeroBytes(chain)
		if err != nil {
			return nil, nil, err
		}
		priv, chain = childPriv, childChain
	}
	return priv, chain, nil
}

func slip10Ed25519Child(parentPriv, parentChain []byte, index uint32) ([]byte, []byte, error) {
	if len(parentPriv) != 32 || len(parentChain) != 32 {
		return nil, nil, errors.New("invalid SLIP-0010 parent node")
	}
	if index&0x80000000 == 0 {
		return nil, nil, errors.New("SLIP-0010 Ed25519 requires hardened children")
	}
	var data [37]byte
	defer zeroBytes(data[:])
	copy(data[1:33], parentPriv)
	binary.BigEndian.PutUint32(data[33:], index)
	mac := hmac.New(sha512.New, parentChain)
	mac.Write(data[:])
	I := mac.Sum(nil)
	defer zeroBytes(I)
	return append([]byte(nil), I[:32]...), append([]byte(nil), I[32:]...), nil
}
