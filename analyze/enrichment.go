package analyze

import (
	"net"
	"sync"
)

// Verdict constants for enrichment results.
const (
	VerdictClean     = "clean"
	VerdictSuspect   = "suspect"
	VerdictMalicious = "malicious"
	VerdictUnknown   = "unknown"
)

// EnrichmentResult holds threat intelligence for a single IP.
type EnrichmentResult struct {
	IP         string
	Verdict    string
	AbuseScore *int
	IsTor      bool
}

// EnrichmentCache caches results to avoid redundant lookups.
type EnrichmentCache struct {
	mu    sync.RWMutex
	cache map[string]*EnrichmentResult
}

// NewEnrichmentCache creates an empty cache.
func NewEnrichmentCache() *EnrichmentCache {
	return &EnrichmentCache{cache: make(map[string]*EnrichmentResult)}
}

// Get returns a cached result or nil.
func (c *EnrichmentCache) Get(ip string) *EnrichmentResult {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cache[ip]
}

// Set stores a result in the cache.
func (c *EnrichmentCache) Set(ip string, result *EnrichmentResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache[ip] = result
}

// EnrichLocal performs local-only enrichment (RFC-1918 checks, no network calls).
// It is safe to call concurrently.
func EnrichLocal(ip string) *EnrichmentResult {
	result := &EnrichmentResult{IP: ip, Verdict: VerdictUnknown}

	parsed := net.ParseIP(ip)
	if parsed == nil {
		return result
	}

	if isPrivate(parsed) {
		result.Verdict = VerdictClean
		return result
	}

	// Placeholder: in relay mode this would call an external API.
	return result
}

// isPrivate returns true for RFC-1918 and loopback addresses.
func isPrivate(ip net.IP) bool {
	private := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"::1/128",
		"fc00::/7",
	}
	for _, cidr := range private {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
