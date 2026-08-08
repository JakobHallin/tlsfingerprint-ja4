package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestServerServesHTTPSAndShutsDown(t *testing.T) {
	certificateFile, keyFile := writeTestCertificate(t)
	server, err := New(Config{
		CertificateFile:     certificateFile,
		PrivateKeyFile:      keyFile,
		MaxClientHelloBytes: 64 * 1024,
		HandshakeTimeout:    2 * time.Second,
		ReadHeaderTimeout:   2 * time.Second,
		WriteTimeout:        2 * time.Second,
		IdleTimeout:         2 * time.Second,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	serverConn, clientConn := net.Pipe()
	listener := newPipeListener(serverConn)
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- server.Serve(listener)
	}()

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // Ephemeral test certificate.
			DialContext: func(context.Context, string, string) (net.Conn, error) {
				return clientConn, nil
			},
		},
		Timeout: 5 * time.Second,
	}
	response, err := client.Get("https://localhost/")
	if err != nil {
		t.Fatalf("HTTPS GET: %v", err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", response.StatusCode, http.StatusOK)
	}
	if got, want := string(body), "ok\n"; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}

	shutdownContext, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownContext); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
	if err := <-serveDone; !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("Serve() error = %v, want http.ErrServerClosed", err)
	}
}

func TestNewRejectsUnsafeConfig(t *testing.T) {
	certificateFile, keyFile := writeTestCertificate(t)
	valid := Config{
		CertificateFile:     certificateFile,
		PrivateKeyFile:      keyFile,
		MaxClientHelloBytes: 64 * 1024,
		HandshakeTimeout:    time.Second,
		ReadHeaderTimeout:   time.Second,
		WriteTimeout:        time.Second,
		IdleTimeout:         time.Second,
	}

	tests := []struct {
		name   string
		change func(*Config)
	}{
		{name: "missing certificate", change: func(config *Config) { config.CertificateFile = "" }},
		{name: "missing private key", change: func(config *Config) { config.PrivateKeyFile = "" }},
		{name: "ClientHello limit", change: func(config *Config) { config.MaxClientHelloBytes = 0 }},
		{name: "handshake timeout", change: func(config *Config) { config.HandshakeTimeout = 0 }},
		{name: "header timeout", change: func(config *Config) { config.ReadHeaderTimeout = 0 }},
		{name: "write timeout", change: func(config *Config) { config.WriteTimeout = 0 }},
		{name: "idle timeout", change: func(config *Config) { config.IdleTimeout = 0 }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := valid
			tt.change(&config)
			if _, err := New(config); err == nil {
				t.Fatal("New() error = nil, want configuration error")
			}
		})
	}
}

func TestTLSListenerDropsSlowClientAndAcceptsNext(t *testing.T) {
	certificateFile, keyFile := writeTestCertificate(t)
	server, err := New(Config{
		CertificateFile:     certificateFile,
		PrivateKeyFile:      keyFile,
		MaxClientHelloBytes: 64 * 1024,
		HandshakeTimeout:    25 * time.Millisecond,
		ReadHeaderTimeout:   time.Second,
		WriteTimeout:        time.Second,
		IdleTimeout:         time.Second,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	slowServer, slowClient := net.Pipe()
	validServer, validClient := net.Pipe()
	listener := newPipeListener(slowServer, validServer)
	t.Cleanup(func() {
		_ = listener.Close()
		_ = slowClient.Close()
		_ = validClient.Close()
	})
	inspected := &tlsListener{
		Listener:           listener,
		tlsConfig:          server.tlsConfig,
		maxClientHelloSize: server.config.MaxClientHelloBytes,
		handshakeTimeout:   server.config.HandshakeTimeout,
	}

	acceptDone := make(chan struct {
		connection net.Conn
		err        error
	}, 1)
	go func() {
		connection, acceptErr := inspected.Accept()
		acceptDone <- struct {
			connection net.Conn
			err        error
		}{connection: connection, err: acceptErr}
	}()

	validTLS := tls.Client(validClient, &tls.Config{
		InsecureSkipVerify: true, // Ephemeral test certificate.
		ServerName:         "localhost",
		NextProtos:         []string{"http/1.1"},
	})
	clientDone := make(chan error, 1)
	go func() { clientDone <- validTLS.Handshake() }()

	var accepted net.Conn
	select {
	case result := <-acceptDone:
		if result.err != nil {
			t.Fatalf("Accept() error = %v", result.err)
		}
		accepted = result.connection
	case <-time.After(2 * time.Second):
		t.Fatal("Accept() did not proceed after slow-client timeout")
	}
	if err := <-clientDone; err != nil {
		t.Fatalf("valid client handshake: %v", err)
	}
	_ = validClient.Close()
	_ = accepted.Close()
}

type pipeListener struct {
	connections chan net.Conn
	closed      chan struct{}
	closeOnce   sync.Once
}

func newPipeListener(initial ...net.Conn) *pipeListener {
	connections := make(chan net.Conn, len(initial))
	for _, connection := range initial {
		connections <- connection
	}
	return &pipeListener{
		connections: connections,
		closed:      make(chan struct{}),
	}
}

func (listener *pipeListener) Accept() (net.Conn, error) {
	select {
	case connection := <-listener.connections:
		return connection, nil
	case <-listener.closed:
		return nil, net.ErrClosed
	}
}

func (listener *pipeListener) Close() error {
	listener.closeOnce.Do(func() { close(listener.closed) })
	return nil
}

func (listener *pipeListener) Addr() net.Addr {
	return pipeAddress("pipe")
}

type pipeAddress string

func (address pipeAddress) Network() string { return string(address) }
func (address pipeAddress) String() string  { return string(address) + "-listener" }

func writeTestCertificate(t *testing.T) (certificateFile string, keyFile string) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}

	directory := t.TempDir()
	certificateFile = filepath.Join(directory, "server.pem")
	keyFile = filepath.Join(directory, "server-key.pem")
	writePEMFile(t, certificateFile, "CERTIFICATE", certificateDER)
	writePEMFile(t, keyFile, "PRIVATE KEY", privateKeyDER)
	return certificateFile, keyFile
}

func writePEMFile(t *testing.T, path string, blockType string, data []byte) {
	t.Helper()

	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	if err := pem.Encode(file, &pem.Block{Type: blockType, Bytes: data}); err != nil {
		_ = file.Close()
		t.Fatalf("encode %s: %v", path, err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close %s: %v", path, err)
	}
}
