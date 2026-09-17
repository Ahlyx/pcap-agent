package ws

import (
	"strings"
	"testing"
)

func TestRelayDashboardURLKeepsViewerTokenOutOfQuery(t *testing.T) {
	launchURL := relayDashboardURL("0123456789abcdef0123456789abcdef", "viewer-token")
	if !strings.Contains(launchURL, "#relay_session=") {
		t.Fatalf("launch URL %q does not use a fragment", launchURL)
	}
	if strings.Contains(strings.Split(launchURL, "#")[0], "viewer-token") {
		t.Fatalf("launch URL places the viewer token before the fragment: %q", launchURL)
	}
}
