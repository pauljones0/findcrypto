package detector

import "testing"

func TestCanonicalKnownAddress(t *testing.T) {
	cases := []struct {
		name, input, want string
	}{
		{"evm checksum", "0x9858EfFD232B4033E47d90003D41EC34EcaEda94", "0x9858effd232b4033e47d90003d41ec34ecaeda94"},
		{"evm lower", "0x9858effd232b4033e47d90003d41ec34ecaeda94", "0x9858effd232b4033e47d90003d41ec34ecaeda94"},
		{"bitcoin base58", "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA", "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"},
		{"bitcoin bech32 upper", "BC1QCR8TE4KR609GCAWUTMRZA0J4XV80JY8Z306FYU", "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"},
		{"solana", "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk", "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk"},
		{"cosmos", "cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0auqdal4", "cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0auqdal4"},
		{"litecoin", "LUWPbpM43E2p7ZSh8cyTBEkvpHmr3cB8Ez", "LUWPbpM43E2p7ZSh8cyTBEkvpHmr3cB8Ez"},
		{"dogecoin", "DBus3bamQjgJULBJtYXpEzDWQRwF5iwxgC", "DBus3bamQjgJULBJtYXpEzDWQRwF5iwxgC"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CanonicalKnownAddress(tc.input)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("canonical = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCanonicalKnownAddressRejectsMalformed(t *testing.T) {
	for _, input := range []string{
		"", "0x1234", "0x9858EfFD232B4033E47d90003D41EC34EcaEda9z",
		"0x9858efFD232B4033E47d90003D41EC34EcaEda94",
		"1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabB",
		"bc1Qcr8te4kr609gcspgv5zpwggzu982vy53qwqwqrv",
		"cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0auqdal5",
		"not-an-address",
	} {
		if got, err := CanonicalKnownAddress(input); err == nil {
			t.Errorf("accepted %q as %q", input, got)
		}
	}
}
