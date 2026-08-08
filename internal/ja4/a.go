// Package ja4 calculates JA4 TLS client fingerprints.
package ja4

import (
	"encoding/hex"
	"fmt"

	"catchhello/internal/clienthello"
)

// A calculates the human-readable JA4 a section for TLS over TCP.
func A(hello clienthello.ClientHello) string {
	version := effectiveVersion(hello.LegacyVersion, hello.SupportedVersions)
	destination := 'i'
	if hello.ServerNamePresent {
		destination = 'd'
	}

	return fmt.Sprintf(
		"t%s%c%02d%02d%s",
		versionCode(version),
		destination,
		countWithoutGREASE(hello.CipherSuites),
		countWithoutGREASE(hello.ExtensionIDs),
		alpnCode(hello.ALPNProtocols),
	)
}

func effectiveVersion(legacy uint16, supported []uint16) uint16 {
	version := legacy
	for _, candidate := range supported {
		if !isGREASE(candidate) && candidate > version {
			version = candidate
		}
	}
	return version
}

func versionCode(version uint16) string {
	switch version {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	default:
		return "00"
	}
}

func countWithoutGREASE(values []uint16) int {
	count := 0
	for _, value := range values {
		if !isGREASE(value) {
			count++
		}
	}
	if count > 99 {
		return 99
	}
	return count
}

func isGREASE(value uint16) bool {
	high := byte(value >> 8)
	low := byte(value)
	return high == low && low&0x0f == 0x0a
}

func alpnCode(protocols []string) string {
	if len(protocols) == 0 || len(protocols[0]) == 0 {
		return "00"
	}

	protocol := []byte(protocols[0])
	first := protocol[0]
	last := protocol[len(protocol)-1]
	if isASCIIAlphanumeric(first) && isASCIIAlphanumeric(last) {
		return string([]byte{first, last})
	}

	encoded := hex.EncodeToString(protocol)
	return string([]byte{encoded[0], encoded[len(encoded)-1]})
}

func isASCIIAlphanumeric(value byte) bool {
	return value >= '0' && value <= '9' ||
		value >= 'A' && value <= 'Z' ||
		value >= 'a' && value <= 'z'
}
