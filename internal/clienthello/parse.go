package clienthello

import (
	"encoding/binary"
	"errors"
	"fmt"
)

var ErrMalformed = errors.New("malformed ClientHello")

// Parse extracts the JA4-relevant fields from a complete ClientHello handshake
// message, including its four-byte handshake header.
func Parse(handshake []byte) (ClientHello, error) {
	if len(handshake) < 4 {
		return ClientHello{}, malformed("handshake header is incomplete")
	}
	if handshake[0] != 1 {
		return ClientHello{}, malformed("handshake type is %d, not ClientHello", handshake[0])
	}

	declaredLength := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
	if declaredLength != len(handshake)-4 {
		return ClientHello{}, malformed("handshake length is %d, have %d", declaredLength, len(handshake)-4)
	}

	body := newCursor(handshake[4:])
	legacyVersion, ok := body.uint16()
	if !ok {
		return ClientHello{}, malformed("legacy version is incomplete")
	}
	if !body.skip(32) {
		return ClientHello{}, malformed("random is incomplete")
	}
	if _, ok := body.vector8(); !ok {
		return ClientHello{}, malformed("session ID is incomplete")
	}

	cipherBytes, ok := body.vector16()
	if !ok || len(cipherBytes)%2 != 0 {
		return ClientHello{}, malformed("cipher suites are incomplete or have an odd length")
	}
	cipherSuites := uint16Values(cipherBytes)

	if _, ok := body.vector8(); !ok {
		return ClientHello{}, malformed("compression methods are incomplete")
	}

	result := ClientHello{
		LegacyVersion: legacyVersion,
		CipherSuites:  cipherSuites,
	}
	if body.remaining() == 0 {
		return result, nil
	}

	extensionBytes, ok := body.vector16()
	if !ok || body.remaining() != 0 {
		return ClientHello{}, malformed("extensions are incomplete or followed by trailing data")
	}
	if err := parseExtensions(extensionBytes, &result); err != nil {
		return ClientHello{}, err
	}
	return result, nil
}

func parseExtensions(data []byte, result *ClientHello) error {
	extensions := newCursor(data)
	for extensions.remaining() > 0 {
		extensionID, ok := extensions.uint16()
		if !ok {
			return malformed("extension ID is incomplete")
		}
		extensionData, ok := extensions.vector16()
		if !ok {
			return malformed("extension %#04x is incomplete", extensionID)
		}

		result.ExtensionIDs = append(result.ExtensionIDs, extensionID)
		switch extensionID {
		case 0x0000:
			result.ServerNamePresent = true
		case 0x002b:
			values, err := parseUint16Vector8(extensionData, "supported versions")
			if err != nil {
				return err
			}
			result.SupportedVersions = append(result.SupportedVersions, values...)
		case 0x0010:
			protocols, err := parseALPN(extensionData)
			if err != nil {
				return err
			}
			result.ALPNProtocols = append(result.ALPNProtocols, protocols...)
		case 0x000d:
			values, err := parseUint16Vector16(extensionData, "signature algorithms")
			if err != nil {
				return err
			}
			result.SignatureAlgorithms = append(result.SignatureAlgorithms, values...)
		}
	}
	return nil
}

func parseUint16Vector8(data []byte, name string) ([]uint16, error) {
	values := newCursor(data)
	valueBytes, ok := values.vector8()
	if !ok || values.remaining() != 0 || len(valueBytes)%2 != 0 {
		return nil, malformed("%s vector is invalid", name)
	}
	return uint16Values(valueBytes), nil
}

func parseUint16Vector16(data []byte, name string) ([]uint16, error) {
	values := newCursor(data)
	valueBytes, ok := values.vector16()
	if !ok || values.remaining() != 0 || len(valueBytes)%2 != 0 {
		return nil, malformed("%s vector is invalid", name)
	}
	return uint16Values(valueBytes), nil
}

func parseALPN(data []byte) ([]string, error) {
	values := newCursor(data)
	protocolBytes, ok := values.vector16()
	if !ok || values.remaining() != 0 {
		return nil, malformed("ALPN protocol list is invalid")
	}

	protocols := newCursor(protocolBytes)
	var result []string
	for protocols.remaining() > 0 {
		protocol, ok := protocols.vector8()
		if !ok || len(protocol) == 0 {
			return nil, malformed("ALPN protocol is invalid")
		}
		result = append(result, string(protocol))
	}
	return result, nil
}

func uint16Values(data []byte) []uint16 {
	values := make([]uint16, 0, len(data)/2)
	for len(data) >= 2 {
		values = append(values, binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	return values
}

func malformed(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrMalformed, fmt.Sprintf(format, args...))
}

type cursor struct {
	data []byte
	pos  int
}

func newCursor(data []byte) *cursor {
	return &cursor{data: data}
}

func (c *cursor) remaining() int {
	return len(c.data) - c.pos
}

func (c *cursor) skip(length int) bool {
	_, ok := c.take(length)
	return ok
}

func (c *cursor) take(length int) ([]byte, bool) {
	if length < 0 || length > c.remaining() {
		return nil, false
	}
	value := c.data[c.pos : c.pos+length]
	c.pos += length
	return value, true
}

func (c *cursor) uint8() (byte, bool) {
	value, ok := c.take(1)
	if !ok {
		return 0, false
	}
	return value[0], true
}

func (c *cursor) uint16() (uint16, bool) {
	value, ok := c.take(2)
	if !ok {
		return 0, false
	}
	return binary.BigEndian.Uint16(value), true
}

func (c *cursor) vector8() ([]byte, bool) {
	length, ok := c.uint8()
	if !ok {
		return nil, false
	}
	return c.take(int(length))
}

func (c *cursor) vector16() ([]byte, bool) {
	length, ok := c.uint16()
	if !ok {
		return nil, false
	}
	return c.take(int(length))
}
