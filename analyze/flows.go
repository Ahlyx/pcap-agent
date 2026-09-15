package analyze

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

// FlowKey identifies one observed packet direction. CanonicalFlowKey converts
// it to the identity used to aggregate a bidirectional conversation.
type FlowKey struct {
	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16
	Proto   string
}

// Endpoint is one transport endpoint of a session or flow.
type Endpoint struct {
	IP   string
	Port uint16
}

func endpointFromKeySrc(k FlowKey) Endpoint { return Endpoint{IP: k.SrcIP, Port: k.SrcPort} }
func endpointFromKeyDst(k FlowKey) Endpoint { return Endpoint{IP: k.DstIP, Port: k.DstPort} }
func (e Endpoint) String() string           { return fmt.Sprintf("%s:%d", e.IP, e.Port) }

func endpointLess(a, b Endpoint) bool {
	if a.IP != b.IP {
		return a.IP < b.IP
	}
	return a.Port < b.Port
}

// CanonicalFlowKey returns a stable, direction-independent flow identity.
func CanonicalFlowKey(k FlowKey) FlowKey {
	a, b := endpointFromKeySrc(k), endpointFromKeyDst(k)
	if endpointLess(b, a) {
		a, b = b, a
	}
	return FlowKey{SrcIP: a.IP, SrcPort: a.Port, DstIP: b.IP, DstPort: b.Port, Proto: k.Proto}
}

// FlowRecord tracks statistics for one bidirectional conversation. Key keeps
// the first observed direction for display; AB/BA are relative to it.
type FlowRecord struct {
	Key       FlowKey
	Bytes     uint64
	Packets   uint64
	BytesAB   uint64
	PacketsAB uint64
	BytesBA   uint64
	PacketsBA uint64
	FirstSeen time.Time
	LastSeen  time.Time
}

type FlowTable struct {
	mu      sync.RWMutex
	flows   map[FlowKey]*FlowRecord
	timeout time.Duration
}

func NewFlowTable(timeout time.Duration) *FlowTable {
	ft := &FlowTable{flows: make(map[FlowKey]*FlowRecord), timeout: timeout}
	if timeout > 0 {
		go ft.expire()
	}
	return ft
}

func (ft *FlowTable) Update(key FlowKey, bytes uint64) { ft.UpdateAt(key, bytes, time.Now()) }

// UpdateAt adds a packet using its capture timestamp.
func (ft *FlowTable) UpdateAt(key FlowKey, bytes uint64, at time.Time) {
	if at.IsZero() {
		at = time.Now()
	}
	canonical := CanonicalFlowKey(key)
	ft.mu.Lock()
	defer ft.mu.Unlock()
	rec, ok := ft.flows[canonical]
	if !ok {
		rec = &FlowRecord{Key: key, FirstSeen: at}
		ft.flows[canonical] = rec
	}
	rec.Bytes += bytes
	rec.Packets++
	if key == rec.Key {
		rec.BytesAB += bytes
		rec.PacketsAB++
	} else {
		rec.BytesBA += bytes
		rec.PacketsBA++
	}
	rec.LastSeen = at
}

func (ft *FlowTable) ActiveCount() int {
	ft.mu.RLock()
	defer ft.mu.RUnlock()
	return len(ft.flows)
}

func (ft *FlowTable) Snapshot() []FlowRecord {
	ft.mu.RLock()
	defer ft.mu.RUnlock()
	out := make([]FlowRecord, 0, len(ft.flows))
	for _, r := range ft.flows {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key.String() < out[j].Key.String() })
	return out
}

// ExpireAt removes records idle before cutoff. It is explicit for deterministic
// replay/tests and is also used by the background expiry ticker.
func (ft *FlowTable) ExpireAt(cutoff time.Time) {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	for k, r := range ft.flows {
		if r.LastSeen.Before(cutoff) {
			delete(ft.flows, k)
		}
	}
}

func (ft *FlowTable) expire() {
	ticker := time.NewTicker(ft.timeout / 2)
	defer ticker.Stop()
	for now := range ticker.C {
		ft.ExpireAt(now.Add(-ft.timeout))
	}
}

func (k FlowKey) String() string {
	return fmt.Sprintf("%s:%d -> %s:%d (%s)", k.SrcIP, k.SrcPort, k.DstIP, k.DstPort, k.Proto)
}
