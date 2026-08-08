package tlsrecord

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"testing"
)

func TestReadClientHello(t *testing.T) {
	records := readFixture(t, "../../testdata/tls_records.bin")
	want := readFixture(t, "../../testdata/clienthello.bin")

	got, err := ReadClientHello(bytes.NewReader(records), 64*1024)
	if err != nil {
		t.Fatalf("ReadClientHello() error = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("ReadClientHello() returned %d bytes, want %d", len(got), len(want))
	}
}

func TestReadClientHelloAcrossRecords(t *testing.T) {
	want := []byte{clientHelloType, 0, 0, 3, 0xaa, 0xbb, 0xcc}
	records := append(tlsRecord(want[:2]), tlsRecord(want[2:])...)

	got, err := ReadClientHello(bytes.NewReader(records), 64*1024)
	if err != nil {
		t.Fatalf("ReadClientHello() error = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("ReadClientHello() = %x, want %x", got, want)
	}
}

func TestReadClientHelloRejectsInvalidInput(t *testing.T) {
	clientHello := []byte{clientHelloType, 0, 0, 1, 0xaa}

	tests := []struct {
		name     string
		input    []byte
		maxBytes int
		wantErr  error
	}{
		{
			name:     "truncated record header",
			input:    []byte{handshakeRecordType, 3, 1},
			maxBytes: 64,
			wantErr:  io.ErrUnexpectedEOF,
		},
		{
			name:     "truncated record payload",
			input:    []byte{handshakeRecordType, 3, 1, 0, 4, clientHelloType},
			maxBytes: 64,
			wantErr:  io.ErrUnexpectedEOF,
		},
		{
			name:     "unexpected record type",
			input:    tlsRecordWithType(23, clientHello),
			maxBytes: 64,
			wantErr:  ErrUnexpectedRecord,
		},
		{
			name:     "invalid record version",
			input:    []byte{handshakeRecordType, 2, 0, 0, 0},
			maxBytes: 64,
			wantErr:  ErrInvalidRecord,
		},
		{
			name:     "unexpected handshake type",
			input:    tlsRecord([]byte{2, 0, 0, 0}),
			maxBytes: 64,
			wantErr:  ErrUnexpectedHandshake,
		},
		{
			name:     "wire data exceeds limit",
			input:    tlsRecord(clientHello),
			maxBytes: recordHeaderLength + len(clientHello) - 1,
			wantErr:  ErrLimitExceeded,
		},
		{
			name:     "declared handshake exceeds limit",
			input:    tlsRecord([]byte{clientHelloType, 0, 1, 0}),
			maxBytes: 64,
			wantErr:  ErrLimitExceeded,
		},
		{
			name:     "non-positive limit",
			input:    tlsRecord(clientHello),
			maxBytes: 0,
			wantErr:  ErrLimitExceeded,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ReadClientHello(bytes.NewReader(tt.input), tt.maxBytes)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("ReadClientHello() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func tlsRecord(payload []byte) []byte {
	return tlsRecordWithType(handshakeRecordType, payload)
}

func tlsRecordWithType(recordType byte, payload []byte) []byte {
	record := make([]byte, recordHeaderLength+len(payload))
	record[0] = recordType
	record[1] = 3
	record[2] = 1
	binary.BigEndian.PutUint16(record[3:5], uint16(len(payload)))
	copy(record[recordHeaderLength:], payload)
	return record
}

func readFixture(t *testing.T, path string) []byte {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %q: %v", path, err)
	}
	return data
}
