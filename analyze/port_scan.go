package analyze

import (
	"sync"
	"time"
)

// PortScanConfig controls detection thresholds.
type PortScanConfig struct {
	// PortThreshold is how many distinct ports must be hit to trigger an alert.
	PortThreshold int
	// Window is the time window over which hits are counted.
	Window time.Duration
}

// DefaultPortScanConfig returns sensible defaults.
func DefaultPortScanConfig() PortScanConfig {
	return PortScanConfig{
		PortThreshold: 15,
		Window:        60 * time.Second,
	}
}

type portHit struct {
	port uint16
	at   time.Time
}

// PortScanDetector tracks connection attempts per (src, dst) pair.
type PortScanDetector struct {
	mu      sync.Mutex
	cfg     PortScanConfig
	history map[string][]portHit // key: "src->dst"
}

// NewPortScanDetector creates a detector with the given config.
func NewPortScanDetector(cfg PortScanConfig) *PortScanDetector {
	return &PortScanDetector{
		cfg:     cfg,
		history: make(map[string][]portHit),
	}
}

// Record notes a connection attempt from src to dst:port.
func (d *PortScanDetector) Record(src, dst string, port uint16) {
	key := src + "->" + dst
	now := time.Now()
	cutoff := now.Add(-d.cfg.Window)

	d.mu.Lock()
	defer d.mu.Unlock()

	hits := d.history[key]
	valid := hits[:0]
	for _, h := range hits {
		if h.at.After(cutoff) {
			valid = append(valid, h)
		}
	}
	valid = append(valid, portHit{port: port, at: now})
	d.history[key] = valid
}

// PortScanResult holds detection output for a scanning source.
type PortScanResult struct {
	Src      string
	Dst      string
	PortsHit []uint16
	Window   time.Duration
}

// Check returns scan results for any (src, dst) pair exceeding the port threshold.
func (d *PortScanDetector) Check() []PortScanResult {
	d.mu.Lock()
	defer d.mu.Unlock()

	var results []PortScanResult
	for key, hits := range d.history {
		distinct := distinctPorts(hits)
		if len(distinct) >= d.cfg.PortThreshold {
			src, dst := splitKey(key)
			results = append(results, PortScanResult{
				Src:      src,
				Dst:      dst,
				PortsHit: distinct,
				Window:   d.cfg.Window,
			})
		}
	}
	return results
}

func distinctPorts(hits []portHit) []uint16 {
	seen := make(map[uint16]struct{})
	for _, h := range hits {
		seen[h.port] = struct{}{}
	}
	out := make([]uint16, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	return out
}
