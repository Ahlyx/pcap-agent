package analyze

import (
	"sync"
	"time"
)

// TCPState represents the state of a tracked TCP session.
type TCPState int

const (
	StateNew         TCPState = iota
	StateSYN
	StateSYNACK
	StateEstablished
	StateClosed
)

// TCP flag bit masks matching standard TCP header positions.
const (
	tcpFlagFIN = uint8(0x01)
	tcpFlagSYN = uint8(0x02)
	tcpFlagRST = uint8(0x04)
	tcpFlagACK = uint8(0x10)
)

// TCPSession tracks the state of a single TCP session.
type TCPSession struct {
	State    TCPState
	SYNTime  time.Time
	SeqSeen  map[uint32]int
	DataSeen bool
	LastSeen time.Time
}

// TCPAnomaly describes a detected TCP-level anomaly.
type TCPAnomaly struct {
	Subtype string // "syn_flood" | "retransmit" | "rst_injection"
	Key     FlowKey
}

// SessionRecon tracks TCP sessions and detects anomalies in real time.
type SessionRecon struct {
	mu       sync.Mutex
	sessions map[FlowKey]*TCPSession
	halfOpen map[string]int // dst IP → count of half-open (SYN, no SYNACK) sessions
}

// NewSessionRecon creates a ready-to-use SessionRecon.
func NewSessionRecon() *SessionRecon {
	return &SessionRecon{
		sessions: make(map[FlowKey]*TCPSession),
		halfOpen: make(map[string]int),
	}
}

// Record processes a TCP segment for the given flow key and returns any
// anomalies detected immediately. flags is the raw TCP flags byte.
func (r *SessionRecon) Record(key FlowKey, flags uint8, seq uint32) []TCPAnomaly {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()

	sess, exists := r.sessions[key]
	if !exists {
		sess = &TCPSession{
			State:    StateNew,
			SeqSeen:  make(map[uint32]int),
			LastSeen: now,
		}
		r.sessions[key] = sess
	}
	sess.LastSeen = now

	var anomalies []TCPAnomaly

	sess.SeqSeen[seq]++
	if sess.SeqSeen[seq] >= 3 {
		anomalies = append(anomalies, TCPAnomaly{Subtype: "retransmit", Key: key})
	}

	syn := flags&tcpFlagSYN != 0
	ack := flags&tcpFlagACK != 0
	rst := flags&tcpFlagRST != 0
	fin := flags&tcpFlagFIN != 0

	switch {
	case syn && !ack:
		sess.State = StateSYN
		sess.SYNTime = now
		r.halfOpen[key.DstIP]++
		if r.halfOpen[key.DstIP] > 20 {
			anomalies = append(anomalies, TCPAnomaly{Subtype: "syn_flood", Key: key})
		}

	case syn && ack:
		sess.State = StateSYNACK
		// SYN+ACK comes from the server (key.SrcIP), so decrement half-open for it.
		if r.halfOpen[key.SrcIP] > 0 {
			r.halfOpen[key.SrcIP]--
		}

	case ack && !syn && !rst && !fin && sess.State == StateSYNACK:
		sess.State = StateEstablished
		sess.DataSeen = false

	case rst && sess.State == StateEstablished && sess.DataSeen:
		anomalies = append(anomalies, TCPAnomaly{Subtype: "rst_injection", Key: key})
		sess.State = StateClosed

	case fin:
		sess.State = StateClosed
	}

	if sess.State == StateEstablished {
		sess.DataSeen = true
	}

	return anomalies
}

// ExpireStale removes sessions whose LastSeen is before cutoff.
func (r *SessionRecon) ExpireStale(cutoff time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for key, sess := range r.sessions {
		if sess.LastSeen.Before(cutoff) {
			if sess.State == StateSYN && r.halfOpen[key.DstIP] > 0 {
				r.halfOpen[key.DstIP]--
			}
			delete(r.sessions, key)
		}
	}
}
