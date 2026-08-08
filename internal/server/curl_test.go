package server

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"sync"
	"testing"
	"time"
)

func TestCurlReturnsJA4(t *testing.T) {
	curlPath, err := exec.LookPath("curl")
	if err != nil {
		t.Skip("curl is not installed")
	}

	certificateFile, keyFile := writeTestCertificate(t)
	httpsServer, err := New(Config{
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
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	serveDone := make(chan error, 1)
	go func() { serveDone <- httpsServer.Serve(listener) }()
	var shutdownOnce sync.Once
	shutdown := func() {
		shutdownOnce.Do(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if shutdownErr := httpsServer.Shutdown(ctx); shutdownErr != nil {
				t.Errorf("Shutdown() error = %v", shutdownErr)
			}
		})
	}
	t.Cleanup(shutdown)

	commandContext, cancelCommand := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelCommand()
	output, err := exec.CommandContext(
		commandContext,
		curlPath,
		"--silent",
		"--show-error",
		"--fail",
		"--insecure",
		"--noproxy", "*",
		"--max-time", "5",
		"https://"+listener.Addr().String()+"/",
	).CombinedOutput()
	if err != nil {
		t.Fatalf("curl failed: %v\n%s", err, output)
	}

	var response struct {
		JA4 string `json:"ja4"`
	}
	if err := json.Unmarshal(output, &response); err != nil {
		t.Fatalf("decode curl response %q: %v", output, err)
	}
	validJA4 := regexp.MustCompile(`^t[0-9a-z]{2}[di][0-9]{4}[0-9A-Za-z]{2}_[0-9a-f]{12}_[0-9a-f]{12}$`)
	if !validJA4.MatchString(response.JA4) {
		t.Fatalf("curl JA4 = %q, want a valid TLS JA4 fingerprint", response.JA4)
	}

	shutdown()
	if err := <-serveDone; !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("Serve() error = %v, want http.ErrServerClosed", err)
	}
}
