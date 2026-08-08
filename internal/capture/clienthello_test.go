package capture

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"os"
	"testing"
	"time"

	"catchhello/internal/clienthello"
)

func TestClientHelloReplaysConsumedBytes(t *testing.T) {
	records, err := os.ReadFile("../../testdata/tls_records.bin")
	if err != nil {
		t.Fatalf("read TLS records fixture: %v", err)
	}
	wantHello, err := os.ReadFile("../../testdata/clienthello.bin")
	if err != nil {
		t.Fatalf("read ClientHello fixture: %v", err)
	}

	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() {
		_ = serverConn.Close()
		_ = clientConn.Close()
	})
	deadline := time.Now().Add(5 * time.Second)
	_ = serverConn.SetDeadline(deadline)
	_ = clientConn.SetDeadline(deadline)

	writeDone := make(chan error, 1)
	go func() {
		_, writeErr := clientConn.Write(records)
		if writeErr == nil {
			writeErr = clientConn.Close()
		}
		writeDone <- writeErr
	}()

	replayConn, gotHello, err := ClientHello(serverConn, 64*1024)
	if err != nil {
		t.Fatalf("ClientHello() error = %v", err)
	}
	if !bytes.Equal(gotHello, wantHello) {
		t.Fatalf("ClientHello() returned %d bytes, want %d", len(gotHello), len(wantHello))
	}

	gotRecords, err := io.ReadAll(replayConn)
	if err != nil {
		t.Fatalf("read replayed connection: %v", err)
	}
	if !bytes.Equal(gotRecords, records) {
		t.Fatalf("replayed connection returned %d bytes, want %d", len(gotRecords), len(records))
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("write fixture: %v", err)
	}
}

func TestClientHelloAllowsTLSHandshakeToContinue(t *testing.T) {
	certificate := testCertificate(t)
	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() {
		_ = serverConn.Close()
		_ = clientConn.Close()
	})
	deadline := time.Now().Add(5 * time.Second)
	_ = serverConn.SetDeadline(deadline)
	_ = clientConn.SetDeadline(deadline)

	clientTLS := tls.Client(clientConn, &tls.Config{
		InsecureSkipVerify: true, // The test uses an ephemeral self-signed certificate.
		ServerName:         "example.test",
		NextProtos:         []string{"h2", "http/1.1"},
	})
	clientDone := make(chan error, 1)
	go func() {
		clientDone <- clientTLS.Handshake()
	}()

	replayConn, handshake, err := ClientHello(serverConn, 64*1024)
	if err != nil {
		t.Fatalf("ClientHello() error = %v", err)
	}
	parsed, err := clienthello.Parse(handshake)
	if err != nil {
		t.Fatalf("parse captured ClientHello: %v", err)
	}
	if !parsed.ServerNamePresent {
		t.Error("captured ClientHello does not contain expected SNI")
	}

	serverTLS := tls.Server(replayConn, &tls.Config{
		Certificates: []tls.Certificate{certificate},
		NextProtos:   []string{"h2", "http/1.1"},
	})
	if err := serverTLS.Handshake(); err != nil {
		t.Fatalf("server TLS handshake: %v", err)
	}
	if err := <-clientDone; err != nil {
		t.Fatalf("client TLS handshake: %v", err)
	}
}

func testCertificate(t *testing.T) tls.Certificate {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.test"},
		DNSNames:     []string{"example.test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{certificateDER},
		PrivateKey:  privateKey,
	}
}
