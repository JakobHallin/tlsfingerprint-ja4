package ja4

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"catchhello/internal/clienthello"
)

func TestOfficialJA4Example(t *testing.T) {
	hello := officialExampleClientHello()

	if got, want := B(hello), "8daaf6152771"; got != want {
		t.Errorf("B() = %q, want %q", got, want)
	}
	if got, want := C(hello), "e5627efa2ab1"; got != want {
		t.Errorf("C() = %q, want %q", got, want)
	}
	if got, want := Fingerprint(hello), "t13d1516h2_8daaf6152771_e5627efa2ab1"; got != want {
		t.Errorf("Fingerprint() = %q, want %q", got, want)
	}
}

func TestFingerprintForCapturedClientHello(t *testing.T) {
	handshake, err := os.ReadFile("../../testdata/clienthello.bin")
	if err != nil {
		t.Fatalf("read ClientHello fixture: %v", err)
	}
	wantBytes, err := os.ReadFile("../../testdata/ja4.txt")
	if err != nil {
		t.Fatalf("read JA4 fixture: %v", err)
	}
	hello, err := clienthello.Parse(handshake)
	if err != nil {
		t.Fatalf("parse ClientHello fixture: %v", err)
	}

	if got, want := Fingerprint(hello), strings.TrimSpace(string(wantBytes)); got != want {
		t.Fatalf("Fingerprint() = %q, want %q", got, want)
	}
}

func TestBEmptyAndGREASEOnly(t *testing.T) {
	tests := []clienthello.ClientHello{
		{},
		{CipherSuites: []uint16{0x0a0a, 0xfafa}},
	}
	for _, hello := range tests {
		if got, want := B(hello), "000000000000"; got != want {
			t.Errorf("B() = %q, want %q", got, want)
		}
	}
}

func TestCEmptyAfterFiltering(t *testing.T) {
	hello := clienthello.ClientHello{
		ExtensionIDs:        []uint16{0x0000, 0x0010, 0x2a2a},
		SignatureAlgorithms: []uint16{0x0403},
	}
	if got, want := C(hello), "000000000000"; got != want {
		t.Fatalf("C() = %q, want %q", got, want)
	}
}

func TestHashOrderingAndGREASERules(t *testing.T) {
	first := clienthello.ClientHello{
		CipherSuites:        []uint16{0x1302, 0x0a0a, 0x1301},
		ExtensionIDs:        []uint16{0x002b, 0x1a1a, 0x000d},
		SignatureAlgorithms: []uint16{0x0403, 0x2a2a, 0x0804},
	}
	second := clienthello.ClientHello{
		CipherSuites:        []uint16{0x1301, 0x1302},
		ExtensionIDs:        []uint16{0x000d, 0x002b},
		SignatureAlgorithms: []uint16{0x0403, 0x0804},
	}

	if B(first) != B(second) {
		t.Errorf("B() changed with ordering or GREASE: %q != %q", B(first), B(second))
	}
	if C(first) != C(second) {
		t.Errorf("C() changed with extension ordering or GREASE: %q != %q", C(first), C(second))
	}

	second.SignatureAlgorithms[0], second.SignatureAlgorithms[1] =
		second.SignatureAlgorithms[1], second.SignatureAlgorithms[0]
	if C(first) == C(second) {
		t.Errorf("C() did not preserve signature algorithm ordering: %q", C(first))
	}
}

func TestHashesDoNotMutateClientHello(t *testing.T) {
	hello := officialExampleClientHello()
	ciphers := append([]uint16(nil), hello.CipherSuites...)
	extensions := append([]uint16(nil), hello.ExtensionIDs...)
	signatures := append([]uint16(nil), hello.SignatureAlgorithms...)

	_ = Fingerprint(hello)

	if !reflect.DeepEqual(hello.CipherSuites, ciphers) {
		t.Errorf("CipherSuites mutated: got %#v, want %#v", hello.CipherSuites, ciphers)
	}
	if !reflect.DeepEqual(hello.ExtensionIDs, extensions) {
		t.Errorf("ExtensionIDs mutated: got %#v, want %#v", hello.ExtensionIDs, extensions)
	}
	if !reflect.DeepEqual(hello.SignatureAlgorithms, signatures) {
		t.Errorf("SignatureAlgorithms mutated: got %#v, want %#v", hello.SignatureAlgorithms, signatures)
	}
}

func officialExampleClientHello() clienthello.ClientHello {
	return clienthello.ClientHello{
		LegacyVersion:     0x0303,
		SupportedVersions: []uint16{0x0304, 0x0303},
		CipherSuites: []uint16{
			0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f,
			0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
			0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
		},
		ExtensionIDs: []uint16{
			0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017,
			0x002d, 0x000d, 0x0005, 0x0023, 0x0012, 0x002b,
			0xff01, 0x000b, 0x000a, 0x0015,
		},
		ServerNamePresent: true,
		ALPNProtocols:     []string{"h2"},
		SignatureAlgorithms: []uint16{
			0x0403, 0x0804, 0x0401, 0x0503,
			0x0805, 0x0501, 0x0806, 0x0601,
		},
	}
}
