package ws

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewServerBindsLoopbackByDefault(t *testing.T) {
	server := NewServer(7777, NewHub())
	if server.listenAddr != "127.0.0.1" {
		t.Fatalf("listenAddr = %q; want 127.0.0.1", server.listenAddr)
	}
}

func TestAllowedOrigins(t *testing.T) {
	allowed := []string{
		"https://ahlyxlabs.com",
		"https://www.ahlyxlabs.com",
		"http://localhost:4173",
		"http://127.0.0.1:3000",
		"http://[::1]:8080",
	}
	for _, origin := range allowed {
		req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:7777/ws", nil)
		req.Header.Set("Origin", origin)
		if !isAllowedOrigin(req) {
			t.Errorf("origin %q was rejected", origin)
		}
	}

	rejected := []string{
		"", "https://example.com", "https://evil.ahlyxlabs.com", "http://ahlyxlabs.com",
		"file://", "https://ahlyxlabs.com/path", "https://ahlyxlabs.com?token=secret", "https://user@ahlyxlabs.com",
	}
	for _, origin := range rejected {
		req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:7777/ws", nil)
		req.Header.Set("Origin", origin)
		if isAllowedOrigin(req) {
			t.Errorf("origin %q was accepted", origin)
		}
	}
}
