package analyze

import (
	"sort"
	"sync"
)

// TalkerCounter tracks bytes sent per source IP.
type TalkerCounter struct {
	mu     sync.RWMutex
	counts map[string]uint64
}

// NewTalkerCounter creates an empty counter.
func NewTalkerCounter() *TalkerCounter {
	return &TalkerCounter{counts: make(map[string]uint64)}
}

// Record adds bytes to the counter for ip.
func (tc *TalkerCounter) Record(ip string, bytes uint64) {
	tc.mu.Lock()
	tc.counts[ip] += bytes
	tc.mu.Unlock()
}

// TopN returns the top n IPs by byte count, sorted descending.
func (tc *TalkerCounter) TopN(n int) []TalkerSnapshot {
	tc.mu.RLock()
	defer tc.mu.RUnlock()

	all := make([]TalkerSnapshot, 0, len(tc.counts))
	for ip, b := range tc.counts {
		all = append(all, TalkerSnapshot{IP: ip, Bytes: b})
	}
	sort.Slice(all, func(i, j int) bool {
		return all[i].Bytes > all[j].Bytes
	})
	if n > len(all) {
		n = len(all)
	}
	return all[:n]
}

// TalkerSnapshot is a point-in-time byte count for one IP.
type TalkerSnapshot struct {
	IP    string
	Bytes uint64
}
