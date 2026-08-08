package ja4

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"catchhello/internal/clienthello"
)

const emptyHash = "000000000000"

// Fingerprint calculates a complete JA4 TLS client fingerprint.
func Fingerprint(hello clienthello.ClientHello) string {
	return A(hello) + "_" + B(hello) + "_" + C(hello)
}

// B calculates the JA4 cipher hash section.
func B(hello clienthello.ClientHello) string {
	ciphers := withoutGREASE(hello.CipherSuites)
	if len(ciphers) == 0 {
		return emptyHash
	}
	sort.Slice(ciphers, func(i, j int) bool { return ciphers[i] < ciphers[j] })
	return hash12(joinUint16Hex(ciphers))
}

// C calculates the JA4 extension and signature-algorithm hash section.
func C(hello clienthello.ClientHello) string {
	extensions := make([]uint16, 0, len(hello.ExtensionIDs))
	for _, extensionID := range hello.ExtensionIDs {
		if isGREASE(extensionID) || extensionID == 0x0000 || extensionID == 0x0010 {
			continue
		}
		extensions = append(extensions, extensionID)
	}
	if len(extensions) == 0 {
		return emptyHash
	}
	sort.Slice(extensions, func(i, j int) bool { return extensions[i] < extensions[j] })

	raw := joinUint16Hex(extensions)
	signatures := withoutGREASE(hello.SignatureAlgorithms)
	if len(signatures) > 0 {
		raw += "_" + joinUint16Hex(signatures)
	}
	return hash12(raw)
}

func withoutGREASE(values []uint16) []uint16 {
	filtered := make([]uint16, 0, len(values))
	for _, value := range values {
		if !isGREASE(value) {
			filtered = append(filtered, value)
		}
	}
	return filtered
}

func joinUint16Hex(values []uint16) string {
	if len(values) == 0 {
		return ""
	}
	var result strings.Builder
	result.Grow(len(values)*5 - 1)
	for index, value := range values {
		if index > 0 {
			result.WriteByte(',')
		}
		_, _ = fmt.Fprintf(&result, "%04x", value)
	}
	return result.String()
}

func hash12(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])[:12]
}
