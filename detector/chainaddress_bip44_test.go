package detector

import "testing"

func TestBIP44AddressEncodersRefuseInvalidPublicKeys(t *testing.T) {
	for name, encode := range map[string]func([]byte) (string, error){
		"litecoin": p2pkhAddressEncoder(48),
		"dogecoin": p2pkhAddressEncoder(30),
		"cosmos":   cosmosAccountAddress,
	} {
		for _, bad := range [][]byte{nil, make([]byte, 32), make([]byte, 33), append([]byte{4}, make([]byte, 32)...)} {
			if _, err := encode(bad); err == nil {
				t.Errorf("%s accepted invalid public key %x", name, bad)
			}
		}
	}
}

func TestBech32EncodeValuesValidation(t *testing.T) {
	if _, err := bech32EncodeValues("", []int{0}); err == nil {
		t.Error("empty HRP must fail")
	}
	if _, err := bech32EncodeValues("cosmos", []int{32}); err == nil {
		t.Error("out-of-range data value must fail")
	}
	if _, err := bech32EncodeValues("cosmos\x1f", []int{0}); err == nil {
		t.Error("control character in HRP must fail")
	}
	if _, err := bech32EncodeValues("cosmos", make([]int, 84)); err == nil {
		t.Error("overlong Bech32 string must fail")
	}
}
