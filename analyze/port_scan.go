package analyze

import (
	"sort"
	"sync"
	"time"
)

type PortScanConfig struct {
	PortThreshold int
	Window        time.Duration
}

func DefaultPortScanConfig() PortScanConfig {
	return PortScanConfig{PortThreshold: 15, Window: 10 * time.Second}
}

type portHit struct {
	port uint16
	at   time.Time
}
type scanKey struct{ src, dst string }
type PortScanDetector struct {
	mu      sync.Mutex
	cfg     PortScanConfig
	history map[scanKey][]portHit
}

func NewPortScanDetector(cfg PortScanConfig) *PortScanDetector {
	return &PortScanDetector{cfg: cfg, history: make(map[scanKey][]portHit)}
}
func (d *PortScanDetector) Record(src, dst string, port uint16) {
	d.RecordAt(src, dst, port, time.Now())
}
func (d *PortScanDetector) RecordAt(src, dst string, port uint16, at time.Time) {
	if at.IsZero() {
		at = time.Now()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	k := scanKey{src: src, dst: dst}
	d.history[k] = append(pruneHits(d.history[k], at.Add(-d.cfg.Window)), portHit{port: port, at: at})
}

type PortScanResult struct {
	Src, Dst string
	PortsHit []uint16
	Window   time.Duration
}

func (d *PortScanDetector) Check() []PortScanResult { return d.CheckAt(time.Now()) }
func (d *PortScanDetector) CheckAt(now time.Time) []PortScanResult {
	d.mu.Lock()
	defer d.mu.Unlock()
	results := make([]PortScanResult, 0)
	for k, old := range d.history {
		hits := pruneHits(old, now.Add(-d.cfg.Window))
		if len(hits) == 0 {
			delete(d.history, k)
			continue
		}
		d.history[k] = hits
		ports := distinctPorts(hits)
		if len(ports) >= d.cfg.PortThreshold {
			results = append(results, PortScanResult{Src: k.src, Dst: k.dst, PortsHit: ports, Window: d.cfg.Window})
		}
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].Src != results[j].Src {
			return results[i].Src < results[j].Src
		}
		return results[i].Dst < results[j].Dst
	})
	return results
}
func pruneHits(hits []portHit, cutoff time.Time) []portHit {
	valid := hits[:0]
	for _, h := range hits {
		if !h.at.Before(cutoff) {
			valid = append(valid, h)
		}
	}
	return valid
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
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
