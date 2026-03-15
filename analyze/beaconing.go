package analyze

import (
	"math"
	"sync"
	"time"
)

// BeaconingConfig controls detection sensitivity.
type BeaconingConfig struct {
	// MinConnections is the minimum number of connections before scoring.
	MinConnections int
	// MaxJitterPct is the allowed coefficient of variation (stddev/mean) for
	// intervals to be considered regular (0.0–1.0).
	MaxJitterPct float64
	// Window is how far back to look for connection timestamps.
	Window time.Duration
}

// DefaultBeaconingConfig returns sensible defaults.
func DefaultBeaconingConfig() BeaconingConfig {
	return BeaconingConfig{
		MinConnections: 5,
		MaxJitterPct:   0.20,
		Window:         10 * time.Minute,
	}
}

// BeaconingDetector tracks outbound connection times per (src, dst) pair.
type BeaconingDetector struct {
	mu      sync.Mutex
	cfg     BeaconingConfig
	history map[string][]time.Time // key: "src->dst"
}

// NewBeaconingDetector creates a detector with the given config.
func NewBeaconingDetector(cfg BeaconingConfig) *BeaconingDetector {
	return &BeaconingDetector{
		cfg:     cfg,
		history: make(map[string][]time.Time),
	}
}

// Record adds a connection event for the (src, dst) pair.
func (d *BeaconingDetector) Record(src, dst string) {
	key := src + "->" + dst
	now := time.Now()
	cutoff := now.Add(-d.cfg.Window)

	d.mu.Lock()
	defer d.mu.Unlock()

	ts := d.history[key]
	// Prune old entries.
	valid := ts[:0]
	for _, t := range ts {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	valid = append(valid, now)
	d.history[key] = valid
}

// BeaconingResult holds detection output for one pair.
type BeaconingResult struct {
	Src        string
	Dst        string
	Count      int
	IntervalMS float64
}

// Check returns beaconing results for any (src, dst) pair that exceeds
// the configured thresholds.
func (d *BeaconingDetector) Check() []BeaconingResult {
	d.mu.Lock()
	defer d.mu.Unlock()

	var results []BeaconingResult
	for key, ts := range d.history {
		if len(ts) < d.cfg.MinConnections {
			continue
		}
		intervals := computeIntervals(ts)
		mean := meanFloat(intervals)
		if mean == 0 {
			continue
		}
		cv := stddevFloat(intervals) / mean
		if cv <= d.cfg.MaxJitterPct {
			src, dst := splitKey(key)
			results = append(results, BeaconingResult{
				Src:        src,
				Dst:        dst,
				Count:      len(ts),
				IntervalMS: mean,
			})
		}
	}
	return results
}

// computeIntervals returns millisecond gaps between sorted timestamps.
func computeIntervals(ts []time.Time) []float64 {
	if len(ts) < 2 {
		return nil
	}
	out := make([]float64, len(ts)-1)
	for i := 1; i < len(ts); i++ {
		out[i-1] = float64(ts[i].Sub(ts[i-1]).Milliseconds())
	}
	return out
}

func meanFloat(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range vals {
		sum += v
	}
	return sum / float64(len(vals))
}

func stddevFloat(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	m := meanFloat(vals)
	variance := 0.0
	for _, v := range vals {
		d := v - m
		variance += d * d
	}
	return math.Sqrt(variance / float64(len(vals)))
}

func splitKey(key string) (src, dst string) {
	for i := 0; i < len(key)-1; i++ {
		if key[i] == '-' && key[i+1] == '>' {
			return key[:i], key[i+2:]
		}
	}
	return key, ""
}
