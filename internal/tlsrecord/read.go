// Package tlsrecord reads TLS records containing a ClientHello handshake.
package tlsrecord

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	recordHeaderLength    = 5
	handshakeHeaderLength = 4
	handshakeRecordType   = 22
	clientHelloType       = 1
)

var (
	ErrInvalidRecord       = errors.New("invalid TLS record")
	ErrLimitExceeded       = errors.New("ClientHello byte limit exceeded")
	ErrUnexpectedRecord    = errors.New("unexpected TLS record type")
	ErrUnexpectedHandshake = errors.New("unexpected TLS handshake type")
)

// ReadClientHello reads and returns a ClientHello handshake message, including
// its four-byte handshake header.
func ReadClientHello(r io.Reader, maxBytes int) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, fmt.Errorf("%w: limit is %d", ErrLimitExceeded, maxBytes)
	}

	var handshake []byte
	totalRead := 0
	expectedLength := 0

	for {
		if totalRead+recordHeaderLength > maxBytes {
			return nil, fmt.Errorf("%w: limit is %d bytes", ErrLimitExceeded, maxBytes)
		}

		header := make([]byte, recordHeaderLength)
		if _, err := io.ReadFull(r, header); err != nil {
			return nil, fmt.Errorf("read TLS record header: %w", err)
		}
		totalRead += recordHeaderLength

		recordLength := int(binary.BigEndian.Uint16(header[3:5]))
		if header[1] != 3 {
			return nil, fmt.Errorf("%w: unsupported version %d.%d", ErrInvalidRecord, header[1], header[2])
		}
		if totalRead+recordLength > maxBytes {
			return nil, fmt.Errorf("%w: limit is %d bytes", ErrLimitExceeded, maxBytes)
		}
		if header[0] != handshakeRecordType {
			return nil, fmt.Errorf("%w: got %d", ErrUnexpectedRecord, header[0])
		}

		payload := make([]byte, recordLength)
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, fmt.Errorf("read TLS record payload: %w", err)
		}
		totalRead += recordLength
		handshake = append(handshake, payload...)

		if len(handshake) < handshakeHeaderLength {
			continue
		}
		if handshake[0] != clientHelloType {
			return nil, fmt.Errorf("%w: got %d", ErrUnexpectedHandshake, handshake[0])
		}
		if expectedLength == 0 {
			handshakeLength := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
			expectedLength = handshakeHeaderLength + handshakeLength
			minimumWireLength := totalRead + expectedLength - len(handshake)
			if minimumWireLength > maxBytes {
				return nil, fmt.Errorf("%w: declared handshake needs at least %d bytes", ErrLimitExceeded, minimumWireLength)
			}
		}
		if len(handshake) >= expectedLength {
			return handshake[:expectedLength], nil
		}
	}
}
