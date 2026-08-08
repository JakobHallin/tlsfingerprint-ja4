// Package server serves HTTPS after inspecting each connection's ClientHello.
package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"

	"catchhello/internal/capture"
)

// Config contains the HTTPS server's local settings.
type Config struct {
	Address             string
	CertificateFile     string
	PrivateKeyFile      string
	MaxClientHelloBytes int
	HandshakeTimeout    time.Duration
	ReadHeaderTimeout   time.Duration
	WriteTimeout        time.Duration
	IdleTimeout         time.Duration
}

// Server is an HTTPS server that inspects ClientHello messages before TLS.
type Server struct {
	address    string
	tlsConfig  *tls.Config
	httpServer *http.Server
	config     Config
}

// New loads the configured certificate and constructs a server.
func New(config Config) (*Server, error) {
	if config.Address == "" {
		config.Address = ":8443"
	}
	if config.CertificateFile == "" || config.PrivateKeyFile == "" {
		return nil, fmt.Errorf("certificate and private key files are required")
	}
	if config.MaxClientHelloBytes <= 0 {
		return nil, fmt.Errorf("maximum ClientHello size must be positive")
	}
	if config.HandshakeTimeout <= 0 {
		return nil, fmt.Errorf("handshake timeout must be positive")
	}
	if config.ReadHeaderTimeout <= 0 {
		return nil, fmt.Errorf("read header timeout must be positive")
	}
	if config.WriteTimeout <= 0 {
		return nil, fmt.Errorf("write timeout must be positive")
	}
	if config.IdleTimeout <= 0 {
		return nil, fmt.Errorf("idle timeout must be positive")
	}

	certificate, err := tls.LoadX509KeyPair(config.CertificateFile, config.PrivateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load TLS certificate: %w", err)
	}

	handler := http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = response.Write([]byte("ok\n"))
	})
	return &Server{
		address: config.Address,
		config:  config,
		tlsConfig: &tls.Config{
			Certificates: []tls.Certificate{certificate},
			MinVersion:   tls.VersionTLS12,
			NextProtos:   []string{"http/1.1"},
		},
		httpServer: &http.Server{
			Handler:           handler,
			ReadHeaderTimeout: config.ReadHeaderTimeout,
			WriteTimeout:      config.WriteTimeout,
			IdleTimeout:       config.IdleTimeout,
		},
	}, nil
}

// ListenAndServe listens on the configured address and serves HTTPS.
func (server *Server) ListenAndServe() error {
	listener, err := net.Listen("tcp", server.address)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", server.address, err)
	}
	return server.Serve(listener)
}

// Serve serves HTTPS connections accepted by listener.
func (server *Server) Serve(listener net.Listener) error {
	inspected := &tlsListener{
		Listener:           listener,
		tlsConfig:          server.tlsConfig,
		maxClientHelloSize: server.config.MaxClientHelloBytes,
		handshakeTimeout:   server.config.HandshakeTimeout,
	}
	return server.httpServer.Serve(inspected)
}

// Shutdown gracefully stops the server.
func (server *Server) Shutdown(ctx context.Context) error {
	return server.httpServer.Shutdown(ctx)
}

type tlsListener struct {
	net.Listener
	tlsConfig          *tls.Config
	maxClientHelloSize int
	handshakeTimeout   time.Duration
}

func (listener *tlsListener) Accept() (net.Conn, error) {
	for {
		connection, err := listener.Listener.Accept()
		if err != nil {
			return nil, err
		}

		deadline := time.Now().Add(listener.handshakeTimeout)
		if err := connection.SetDeadline(deadline); err != nil {
			_ = connection.Close()
			continue
		}
		replayed, _, err := capture.ClientHello(connection, listener.maxClientHelloSize)
		if err != nil {
			_ = connection.Close()
			continue
		}

		tlsConnection := tls.Server(replayed, listener.tlsConfig)
		if err := tlsConnection.Handshake(); err != nil {
			_ = tlsConnection.Close()
			continue
		}
		if err := tlsConnection.SetDeadline(time.Time{}); err != nil {
			_ = tlsConnection.Close()
			continue
		}
		return tlsConnection, nil
	}
}
