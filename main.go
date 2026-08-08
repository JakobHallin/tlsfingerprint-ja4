package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"catchhello/internal/server"
)

func main() {
	log.SetFlags(0)
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	address := flag.String("addr", ":8443", "TCP address to listen on")
	certificateFile := flag.String("cert", "certs/server.pem", "TLS certificate file")
	privateKeyFile := flag.String("key", "certs/server-key.pem", "TLS private key file")
	maxClientHelloBytes := flag.Int("max-client-hello-bytes", 64*1024, "maximum ClientHello wire bytes")
	handshakeTimeout := flag.Duration("handshake-timeout", 5*time.Second, "TLS handshake timeout")
	readHeaderTimeout := flag.Duration("read-header-timeout", 5*time.Second, "HTTP request header timeout")
	writeTimeout := flag.Duration("write-timeout", 10*time.Second, "HTTP response write timeout")
	idleTimeout := flag.Duration("idle-timeout", 30*time.Second, "HTTP keep-alive idle timeout")
	shutdownTimeout := flag.Duration("shutdown-timeout", 5*time.Second, "graceful shutdown timeout")
	flag.Parse()

	httpsServer, err := server.New(server.Config{
		Address:             *address,
		CertificateFile:     *certificateFile,
		PrivateKeyFile:      *privateKeyFile,
		MaxClientHelloBytes: *maxClientHelloBytes,
		HandshakeTimeout:    *handshakeTimeout,
		ReadHeaderTimeout:   *readHeaderTimeout,
		WriteTimeout:        *writeTimeout,
		IdleTimeout:         *idleTimeout,
	})
	if err != nil {
		return err
	}

	shutdownSignal, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	serveDone := make(chan error, 1)
	go func() {
		serveDone <- httpsServer.ListenAndServe()
	}()
	log.Printf("listening on https://%s", *address)

	select {
	case err := <-serveDone:
		return err
	case <-shutdownSignal.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), *shutdownTimeout)
		defer cancel()
		if err := httpsServer.Shutdown(shutdownContext); err != nil {
			return fmt.Errorf("shut down server: %w", err)
		}
		if err := <-serveDone; err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}
