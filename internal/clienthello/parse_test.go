package clienthello

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestParseJA4Fields(t *testing.T) {
	handshake := clientHelloHandshake(
		0x0303,
		[]uint16{0x0a0a, 0x1301, 0x1302},
		tlsExtension(0x0000, nil),
		tlsExtension(0x002b, []byte{4, 0x03, 0x04, 0x03, 0x03}),
		tlsExtension(0x0010, []byte{0, 12, 2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'}),
		tlsExtension(0x000d, []byte{0, 4, 0x04, 0x03, 0x08, 0x04}),
		tlsExtension(0x0017, nil),
	)

	got, err := Parse(handshake)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	want := ClientHello{
		LegacyVersion:       0x0303,
		SupportedVersions:   []uint16{0x0304, 0x0303},
		CipherSuites:        []uint16{0x0a0a, 0x1301, 0x1302},
		ExtensionIDs:        []uint16{0x0000, 0x002b, 0x0010, 0x000d, 0x0017},
		ServerNamePresent:   true,
		ALPNProtocols:       []string{"h2", "http/1.1"},
		SignatureAlgorithms: []uint16{0x0403, 0x0804},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Parse() = %#v, want %#v", got, want)
	}
}

func TestParseCapturedClientHello(t *testing.T) {
	handshake, err := os.ReadFile("../../testdata/clienthello.bin")
	if err != nil {
		t.Fatalf("read ClientHello fixture: %v", err)
	}
	recordedJA4, err := os.ReadFile("../../testdata/ja4.txt")
	if err != nil {
		t.Fatalf("read JA4 fixture: %v", err)
	}

	got, err := Parse(handshake)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if got.LegacyVersion != 0x0303 {
		t.Errorf("LegacyVersion = %#04x, want %#04x", got.LegacyVersion, 0x0303)
	}
	if !containsUint16(got.SupportedVersions, 0x0304) {
		t.Errorf("SupportedVersions = %#v, want TLS 1.3", got.SupportedVersions)
	}
	if !got.ServerNamePresent {
		t.Error("ServerNamePresent = false, want true")
	}
	if len(got.ALPNProtocols) == 0 || got.ALPNProtocols[0] != "h2" {
		t.Errorf("ALPNProtocols = %#v, want first protocol h2", got.ALPNProtocols)
	}
	if !strings.HasPrefix(string(recordedJA4), "t13d") {
		t.Fatalf("recorded JA4 %q does not support fixture assertions", recordedJA4)
	}
}

func TestParseRejectsEveryTruncatedPrefix(t *testing.T) {
	valid := clientHelloHandshake(
		0x0303,
		[]uint16{0x1301},
		tlsExtension(0x002b, []byte{2, 0x03, 0x04}),
	)

	for length := 0; length < len(valid); length++ {
		_, err := Parse(valid[:length])
		if !errors.Is(err, ErrMalformed) {
			t.Fatalf("Parse(valid[:%d]) error = %v, want ErrMalformed", length, err)
		}
	}
}

func TestParseRejectsMalformedJA4Vectors(t *testing.T) {
	tests := []struct {
		name      string
		extension []byte
	}{
		{
			name:      "supported versions length",
			extension: tlsExtension(0x002b, []byte{3, 0x03, 0x04, 0x03}),
		},
		{
			name:      "ALPN list length",
			extension: tlsExtension(0x0010, []byte{0, 3, 2, 'h'}),
		},
		{
			name:      "empty ALPN protocol",
			extension: tlsExtension(0x0010, []byte{0, 1, 0}),
		},
		{
			name:      "signature algorithms odd length",
			extension: tlsExtension(0x000d, []byte{0, 3, 0x04, 0x03, 0x08}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handshake := clientHelloHandshake(0x0303, []uint16{0x1301}, tt.extension)
			_, err := Parse(handshake)
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("Parse() error = %v, want ErrMalformed", err)
			}
		})
	}
}

func containsUint16(values []uint16, want uint16) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func clientHelloHandshake(legacyVersion uint16, cipherSuites []uint16, extensions ...[]byte) []byte {
	var body bytes.Buffer
	_ = binary.Write(&body, binary.BigEndian, legacyVersion)
	body.Write(make([]byte, 32))
	body.WriteByte(0)
	_ = binary.Write(&body, binary.BigEndian, uint16(len(cipherSuites)*2))
	for _, cipherSuite := range cipherSuites {
		_ = binary.Write(&body, binary.BigEndian, cipherSuite)
	}
	body.WriteByte(1)
	body.WriteByte(0)

	extensionLength := 0
	for _, extension := range extensions {
		extensionLength += len(extension)
	}
	_ = binary.Write(&body, binary.BigEndian, uint16(extensionLength))
	for _, extension := range extensions {
		body.Write(extension)
	}

	handshake := []byte{1, byte(body.Len() >> 16), byte(body.Len() >> 8), byte(body.Len())}
	return append(handshake, body.Bytes()...)
}

func tlsExtension(extensionID uint16, data []byte) []byte {
	extension := make([]byte, 4+len(data))
	binary.BigEndian.PutUint16(extension[0:2], extensionID)
	binary.BigEndian.PutUint16(extension[2:4], uint16(len(data)))
	copy(extension[4:], data)
	return extension
}
