//go:build browsertest

package server

import "testing"

const defaultChromeImage = "selenium/standalone-chrome:latest"

func TestChromeReturnsJA4(t *testing.T) {
	testBrowserReturnsJA4(t, browserTestConfig{
		name:            "Chrome",
		webdriverName:   "chrome",
		defaultImage:    defaultChromeImage,
		imageEnvVarName: "JA4_CHROME_IMAGE",
		userAgentMarker: "Chrome/",
	})
}
