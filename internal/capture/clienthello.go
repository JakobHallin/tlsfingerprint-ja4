// Package capture inspects a connection without consuming bytes needed by its
// eventual TLS server.
package capture

import (
	"bytes"
	"io"
	"net"

	"catchhello/internal/tlsrecord"
)

// ClientHello reads a ClientHello from conn and returns both the handshake and
// a connection that replays all bytes consumed during inspection.
func ClientHello(conn net.Conn, maxBytes int) (net.Conn, []byte, error) {
	var captured bytes.Buffer
	handshake, err := tlsrecord.ReadClientHello(io.TeeReader(conn, &captured), maxBytes)
	if err != nil {
		return nil, nil, err
	}

	replayed := io.MultiReader(bytes.NewReader(captured.Bytes()), conn)
	return &replayConn{Conn: conn, reader: replayed}, handshake, nil
}

type replayConn struct {
	net.Conn
	reader io.Reader
}

func (conn *replayConn) Read(destination []byte) (int, error) {
	return conn.reader.Read(destination)
}
