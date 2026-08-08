//go:build browsertest

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

const defaultFirefoxImage = "selenium/standalone-firefox:latest"

func TestFirefoxReturnsJA4(t *testing.T) {
	testBrowserReturnsJA4(t, browserTestConfig{
		name:            "Firefox",
		webdriverName:   "firefox",
		defaultImage:    defaultFirefoxImage,
		imageEnvVarName: "JA4_FIREFOX_IMAGE",
		userAgentMarker: "Firefox/",
	})
}

type browserTestConfig struct {
	name            string
	webdriverName   string
	defaultImage    string
	imageEnvVarName string
	userAgentMarker string
}

func testBrowserReturnsJA4(t *testing.T, config browserTestConfig) {
	t.Helper()
	dockerPath, err := exec.LookPath("docker")
	if err != nil {
		t.Skip("Docker is not installed")
	}
	if output, err := exec.Command(dockerPath, "info", "--format", "{{.ServerVersion}}").CombinedOutput(); err != nil {
		t.Skipf("Docker daemon is unavailable: %v: %s", err, output)
	}

	httpsServer, listener := startBrowserTestServer(t)
	shutdownServer := shutdownTestServer(t, httpsServer)
	t.Cleanup(shutdownServer)

	driverAddress := unusedLoopbackAddress(t)
	_, driverPort, err := net.SplitHostPort(driverAddress)
	if err != nil {
		t.Fatalf("split WebDriver address %q: %v", driverAddress, err)
	}
	containerName := fmt.Sprintf("ja4-%s-%d", config.webdriverName, time.Now().UnixNano())
	image := os.Getenv(config.imageEnvVarName)
	if image == "" {
		image = config.defaultImage
	}

	var containerLog synchronizedBuffer
	container := exec.Command(
		dockerPath,
		"run", "--rm",
		"--name", containerName,
		"--shm-size", "2g",
		"--add-host", "host.docker.internal:host-gateway",
		"--publish", "127.0.0.1:"+driverPort+":4444",
		image,
	)
	container.Stdout = &containerLog
	container.Stderr = &containerLog
	if err := container.Start(); err != nil {
		t.Fatalf("start Firefox container: %v", err)
	}
	var stopContainerOnce sync.Once
	stopContainer := func() {
		stopContainerOnce.Do(func() {
			removeContext, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			_ = exec.CommandContext(removeContext, dockerPath, "rm", "--force", containerName).Run()
			_ = container.Wait()
		})
	}
	t.Cleanup(stopContainer)

	webdriverClient := &http.Client{
		Transport: &http.Transport{Proxy: nil},
		Timeout:   10 * time.Second,
	}
	driverURL := "http://" + driverAddress
	waitForWebDriver(t, webdriverClient, driverURL, &containerLog)

	var created struct {
		Value struct {
			SessionID    string `json:"sessionId"`
			Capabilities struct {
				BrowserName    string `json:"browserName"`
				BrowserVersion string `json:"browserVersion"`
			} `json:"capabilities"`
		} `json:"value"`
	}
	createBody := map[string]any{
		"capabilities": map[string]any{
			"alwaysMatch": map[string]any{
				"browserName":         config.webdriverName,
				"acceptInsecureCerts": true,
			},
		},
	}
	if err := webdriverRequest(webdriverClient, http.MethodPost, driverURL+"/session", createBody, &created); err != nil {
		t.Fatalf("create %s session: %v\ncontainer log:\n%s", config.name, err, containerLog.String())
	}
	if created.Value.SessionID == "" {
		t.Fatalf("create %s session returned no session ID\ncontainer log:\n%s", config.name, containerLog.String())
	}
	if !strings.EqualFold(created.Value.Capabilities.BrowserName, config.webdriverName) {
		t.Fatalf("requested %s but WebDriver started browser %q", config.name, created.Value.Capabilities.BrowserName)
	}
	sessionURL := driverURL + "/session/" + created.Value.SessionID
	t.Cleanup(func() {
		_ = webdriverRequest(webdriverClient, http.MethodDelete, sessionURL, nil, nil)
	})

	_, serverPort, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("split server address %q: %v", listener.Addr(), err)
	}
	targetURL := "https://host.docker.internal:" + serverPort + "/"
	if err := webdriverRequest(webdriverClient, http.MethodPost, sessionURL+"/url", map[string]string{"url": targetURL}, nil); err != nil {
		t.Fatalf("navigate %s to server: %v\ncontainer log:\n%s", config.name, err, containerLog.String())
	}
	var executed struct {
		Value struct {
			Body      string `json:"body"`
			UserAgent string `json:"userAgent"`
		} `json:"value"`
	}
	if err := webdriverRequest(
		webdriverClient,
		http.MethodPost,
		sessionURL+"/execute/sync",
		map[string]any{
			"script": "return {body: document.body.innerText, userAgent: navigator.userAgent};",
			"args":   []any{},
		},
		&executed,
	); err != nil {
		t.Fatalf("read %s page: %v\ncontainer log:\n%s", config.name, err, containerLog.String())
	}

	if !strings.Contains(executed.Value.UserAgent, config.userAgentMarker) {
		t.Fatalf("%s reported unexpected user agent %q", config.name, executed.Value.UserAgent)
	}
	if !strings.Contains(executed.Value.Body, "ja4") {
		t.Fatalf("%s page does not contain the JA4 response field: %q", config.name, executed.Value.Body)
	}
	fingerprintPattern := regexp.MustCompile(`t[0-9a-z]{2}[di][0-9]{4}[0-9A-Za-z]{2}_[0-9a-f]{12}_[0-9a-f]{12}`)
	fingerprints := fingerprintPattern.FindAllString(executed.Value.Body, -1)
	if len(fingerprints) != 1 {
		t.Fatalf("%s page should contain exactly one TLS JA4 fingerprint, got %d in %q", config.name, len(fingerprints), executed.Value.Body)
	}
	validJA4 := regexp.MustCompile(`^t[0-9a-z]{2}[di][0-9]{4}[0-9A-Za-z]{2}_[0-9a-f]{12}_[0-9a-f]{12}$`)
	if !validJA4.MatchString(fingerprints[0]) {
		t.Fatalf("%s server response contains invalid TLS JA4 fingerprint %q", config.name, fingerprints[0])
	}
	t.Logf("verified real %s %s (%s), JA4 %s", config.name, created.Value.Capabilities.BrowserVersion, executed.Value.UserAgent, fingerprints[0])
}

func startBrowserTestServer(t *testing.T) (*Server, net.Listener) {
	t.Helper()
	certificateFile, keyFile := writeTestCertificate(t)
	httpsServer, err := New(Config{
		CertificateFile:     certificateFile,
		PrivateKeyFile:      keyFile,
		MaxClientHelloBytes: 64 * 1024,
		HandshakeTimeout:    10 * time.Second,
		ReadHeaderTimeout:   10 * time.Second,
		WriteTimeout:        10 * time.Second,
		IdleTimeout:         10 * time.Second,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	listener, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = httpsServer.Serve(listener) }()
	return httpsServer, listener
}

func shutdownTestServer(t *testing.T, httpsServer *Server) func() {
	t.Helper()
	var once sync.Once
	return func() {
		once.Do(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err := httpsServer.Shutdown(ctx); err != nil {
				t.Errorf("Shutdown() error = %v", err)
			}
		})
	}
}

func unusedLoopbackAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve WebDriver port: %v", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("release WebDriver port: %v", err)
	}
	return address
}

func waitForWebDriver(t *testing.T, client *http.Client, baseURL string, log *synchronizedBuffer) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		response, err := client.Get(baseURL + "/status")
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("browser container did not become ready\n%s", log.String())
}

func webdriverRequest(client *http.Client, method string, url string, requestBody any, responseBody any) error {
	var body io.Reader
	if requestBody != nil {
		encoded, err := json.Marshal(requestBody)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		body = bytes.NewReader(encoded)
	}
	request, err := http.NewRequest(method, url, body)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	if requestBody != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	responseData, err := io.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("WebDriver status %d: %s", response.StatusCode, responseData)
	}
	if responseBody != nil {
		if err := json.Unmarshal(responseData, responseBody); err != nil {
			return fmt.Errorf("decode response %q: %w", responseData, err)
		}
	}
	return nil
}

type synchronizedBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (buffer *synchronizedBuffer) Write(data []byte) (int, error) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.buffer.Write(data)
}

func (buffer *synchronizedBuffer) String() string {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.buffer.String()
}
