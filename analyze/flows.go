package analyze

import (
	"fmt"
	"sync"
	"time"
)

// FlowKey uniquely identifies a bidirectional flow.
type FlowKey struct {
	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16
	Proto   string
}

// FlowRecord tracks statistics for a single flow.
type FlowRecord struct {
	Key       FlowKey
	Bytes     uint64
	Packets   uint64
	FirstSeen time.Time
	LastSeen  time.Time
}

// FlowTable maintains all active flows.
type FlowTable struct {
	mu      sync.RWMutex
	flows   map[FlowKey]*FlowRecord
	timeout time.Duration
}

// NewFlowTable creates a FlowTable with the given idle timeout.
func NewFlowTable(timeout time.Duration) *FlowTable {
	ft := &FlowTable{
		flows:   make(map[FlowKey]*FlowRecord),
		timeout: timeout,
	}
	go ft.expire()
	return ft
}

// Update adds bytes/packets to the matching flow, creating it if needed.
func (ft *FlowTable) Update(key FlowKey, bytes uint64) {
	ft.mu.Lock()
	defer ft.mu.Unlock()

	rec, ok := ft.flows[key]
	if !ok {
		rec = &FlowRecord{Key: key, FirstSeen: time.Now()}
		ft.flows[key] = rec
	}
	rec.Bytes += bytes
	rec.Packets++
	rec.LastSeen = time.Now()
}

// ActiveCount returns the number of flows seen in the last timeout window.
func (ft *FlowTable) ActiveCount() int {
	ft.mu.RLock()
	defer ft.mu.RUnlock()
	return len(ft.flows)
}

// Snapshot returns a copy of all current flow records.
func (ft *FlowTable) Snapshot() []FlowRecord {
	ft.mu.RLock()
	defer ft.mu.RUnlock()
	out := make([]FlowRecord, 0, len(ft.flows))
	for _, r := range ft.flows {
		out = append(out, *r)
	}
	return out
}

// expire periodically removes flows that have been idle longer than the timeout.
func (ft *FlowTable) expire() {
	ticker := time.NewTicker(ft.timeout / 2)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-ft.timeout)
		ft.mu.Lock()
		for k, r := range ft.flows {
			if r.LastSeen.Before(cutoff) {
				delete(ft.flows, k)
			}
		}
		ft.mu.Unlock()
	}
}

// String returns a human-readable flow key.
func (k FlowKey) String() string {
	return fmt.Sprintf("%s:%d -> %s:%d (%s)", k.SrcIP, k.SrcPort, k.DstIP, k.DstPort, k.Proto)
}
