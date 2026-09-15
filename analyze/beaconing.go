package analyze

import (
	"math"
	"sort"
	"sync"
	"time"
)

type BeaconingConfig struct {
	MinConnections int
	MaxJitterPct   float64
	MinSpan        time.Duration
	Window         time.Duration
}

func DefaultBeaconingConfig() BeaconingConfig {
	return BeaconingConfig{MinConnections: 6, MaxJitterPct: 0.20, MinSpan: time.Minute, Window: 10 * time.Minute}
}

type beaconKey struct {
	src, dst string
	dstPort  uint16
}

// BeaconingDetector tracks already-deduplicated local connection attempts.
type BeaconingDetector struct {
	mu      sync.Mutex
	cfg     BeaconingConfig
	history map[beaconKey][]time.Time
}

func NewBeaconingDetector(cfg BeaconingConfig) *BeaconingDetector {
	return &BeaconingDetector{cfg: cfg, history: make(map[beaconKey][]time.Time)}
}
func (d *BeaconingDetector) Record(src, dst string) { d.RecordAt(src, dst, 0, time.Now()) }
func (d *BeaconingDetector) RecordAt(src, dst string, dstPort uint16, at time.Time) {
	if at.IsZero() {
		at = time.Now()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	k := beaconKey{src: src, dst: dst, dstPort: dstPort}
	d.history[k] = append(pruneTimes(d.history[k], at.Add(-d.cfg.Window)), at)
}

type BeaconingResult struct {
	Src, Dst              string
	DstPort               uint16
	Count                 int
	IntervalMS, JitterPct float64
	ObservationSpan       time.Duration
}

func (d *BeaconingDetector) Check() []BeaconingResult { return d.CheckAt(time.Now()) }

// CheckAt prunes stale histories even when no later packets arrive.
func (d *BeaconingDetector) CheckAt(now time.Time) []BeaconingResult {
	d.mu.Lock()
	defer d.mu.Unlock()
	results := make([]BeaconingResult, 0)
	for k, old := range d.history {
		ts := pruneTimes(old, now.Add(-d.cfg.Window))
		if len(ts) == 0 {
			delete(d.history, k)
			continue
		}
		d.history[k] = ts
		if len(ts) < d.cfg.MinConnections {
			continue
		}
		span := ts[len(ts)-1].Sub(ts[0])
		if span < d.cfg.MinSpan {
			continue
		}
		mean := meanFloat(computeIntervals(ts))
		if mean <= 0 {
			continue
		}
		cv := stddevFloat(computeIntervals(ts)) / mean
		if cv <= d.cfg.MaxJitterPct {
			results = append(results, BeaconingResult{Src: k.src, Dst: k.dst, DstPort: k.dstPort, Count: len(ts), IntervalMS: mean, JitterPct: cv, ObservationSpan: span})
		}
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].Src != results[j].Src {
			return results[i].Src < results[j].Src
		}
		if results[i].Dst != results[j].Dst {
			return results[i].Dst < results[j].Dst
		}
		return results[i].DstPort < results[j].DstPort
	})
	return results
}
func pruneTimes(ts []time.Time, cutoff time.Time) []time.Time {
	valid := ts[:0]
	for _, t := range ts {
		if !t.Before(cutoff) {
			valid = append(valid, t)
		}
	}
	return valid
}
func computeIntervals(ts []time.Time) []float64 {
	if len(ts) < 2 {
		return nil
	}
	out := make([]float64, len(ts)-1)
	for i := 1; i < len(ts); i++ {
		out[i-1] = float64(ts[i].Sub(ts[i-1])) / float64(time.Millisecond)
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
		delta := v - m
		variance += delta * delta
	}
	return math.Sqrt(variance / float64(len(vals)))
}
