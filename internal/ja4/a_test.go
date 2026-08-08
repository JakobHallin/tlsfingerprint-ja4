package ja4

import (
	"os"
	"strings"
	"testing"

	"catchhello/internal/clienthello"
)

func TestAForCapturedClientHello(t *testing.T) {
	handshake, err := os.ReadFile("../../testdata/clienthello.bin")
	if err != nil {
		t.Fatalf("read ClientHello fixture: %v", err)
	}
	hello, err := clienthello.Parse(handshake)
	if err != nil {
		t.Fatalf("parse ClientHello fixture: %v", err)
	}

	if got, want := A(hello), "t13d3113h2"; got != want {
		t.Fatalf("A() = %q, want %q", got, want)
	}
}

func TestAUsesJA4Fields(t *testing.T) {
	hello := clienthello.ClientHello{
		LegacyVersion:     0x0303,
		SupportedVersions: []uint16{0x0a0a, 0x0303, 0x0304},
		CipherSuites:      []uint16{0x1a1a, 0x1301, 0x00ff},
		ExtensionIDs:      []uint16{0x2a2a, 0x0000, 0x0010, 0x002b},
		ServerNamePresent: true,
		ALPNProtocols:     []string{"h2", "http/1.1"},
	}

	if got, want := A(hello), "t13d0203h2"; got != want {
		t.Fatalf("A() = %q, want %q", got, want)
	}
}

func TestAVersion(t *testing.T) {
	tests := []struct {
		name      string
		legacy    uint16
		supported []uint16
		want      string
	}{
		{name: "TLS 1.3", supported: []uint16{0x0303, 0x0304}, want: "13"},
		{name: "TLS 1.2 legacy", legacy: 0x0303, want: "12"},
		{name: "TLS 1.1", legacy: 0x0302, want: "11"},
		{name: "TLS 1.0", legacy: 0x0301, want: "10"},
		{name: "SSL 3.0", legacy: 0x0300, want: "s3"},
		{name: "SSL 2.0", legacy: 0x0002, want: "s2"},
		{name: "unknown", legacy: 0x1234, want: "00"},
		{name: "GREASE ignored", legacy: 0x0303, supported: []uint16{0xfafa}, want: "12"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hello := clienthello.ClientHello{
				LegacyVersion:     tt.legacy,
				SupportedVersions: tt.supported,
			}
			if got := A(hello)[1:3]; got != tt.want {
				t.Fatalf("A() version = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestACountsIgnoreOnlyGREASEAndCapAt99(t *testing.T) {
	hello := clienthello.ClientHello{
		LegacyVersion: 0x0303,
		CipherSuites:  append(make([]uint16, 100), 0x1a1a),
		ExtensionIDs:  []uint16{0x0a1a, 0x2a2a},
	}

	if got, want := A(hello), "t12i990100"; got != want {
		t.Fatalf("A() = %q, want %q", got, want)
	}
}

func TestAALPN(t *testing.T) {
	tests := []struct {
		name string
		alpn []string
		want string
	}{
		{name: "none", want: "00"},
		{name: "empty", alpn: []string{""}, want: "00"},
		{name: "single ASCII", alpn: []string{"h"}, want: "hh"},
		{name: "HTTP 1.1", alpn: []string{"http/1.1"}, want: "h1"},
		{name: "non-ASCII byte", alpn: []string{string([]byte{0xab})}, want: "ab"},
		{name: "hex edges", alpn: []string{string([]byte{0x20, 0x61})}, want: "21"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hello := clienthello.ClientHello{LegacyVersion: 0x0303, ALPNProtocols: tt.alpn}
			if got := A(hello)[8:10]; got != tt.want {
				t.Fatalf("A() ALPN = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAWithoutValuesHasFixedWidth(t *testing.T) {
	got := A(clienthello.ClientHello{})
	if got != "t00i000000" {
		t.Fatalf("A() = %q, want %q", got, "t00i000000")
	}
	if len(got) != 10 || strings.Contains(got, "_") {
		t.Fatalf("A() = %q, want ten-character a section", got)
	}
}
