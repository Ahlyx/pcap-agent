package analyze

import (
	"fmt"
	"sync"
	"time"
)

type TCPState int

const (
	StateNew TCPState = iota
	StateSYN
	StateSYNACK
	StateEstablished
	StateClosed
)

const (
	tcpFlagFIN = uint8(0x01)
	tcpFlagSYN = uint8(0x02)
	tcpFlagRST = uint8(0x04)
	tcpFlagACK = uint8(0x10)
)

// SessionKey is a stable identity for both directions of a TCP conversation.
type SessionKey struct {
	A, B  Endpoint
	Proto string
}

func CanonicalSessionKey(k FlowKey) SessionKey {
	a, b := endpointFromKeySrc(k), endpointFromKeyDst(k)
	if endpointLess(b, a) {
		a, b = b, a
	}
	return SessionKey{A: a, B: b, Proto: k.Proto}
}
func (k SessionKey) String() string { return fmt.Sprintf("%s <-> %s (%s)", k.A, k.B, k.Proto) }

type sequenceRange struct{ start, end uint32 }

type TCPSession struct {
	Initiator, Responder Endpoint
	State                TCPState
	SYNTime              time.Time
	DataSeen             bool
	LastSeen             time.Time
	PressureHalfOpen     bool
	ResetReported        bool
	RetransmitReported   bool
	Ranges               map[Endpoint][]sequenceRange
}

type ConnectionAttempt struct {
	SrcIP   string
	SrcPort uint16
	DstIP   string
	DstPort uint16
	At      time.Time
}
type TCPAnomaly struct {
	Subtype string
	Key     FlowKey
	Count   int
}
type TCPRecordResult struct {
	ConnectionAttempt *ConnectionAttempt
	Anomalies         []TCPAnomaly
}

// SessionRecon tracks canonical TCP sessions. It only treats a first
// SYN-without-ACK as a connection attempt, which deduplicates SYN retransmits.
type SessionRecon struct {
	mu                sync.Mutex
	sessions          map[SessionKey]*TCPSession
	halfOpen          map[Endpoint]map[SessionKey]struct{}
	pressureReported  map[Endpoint]bool
	HalfOpenThreshold int
}

func NewSessionRecon() *SessionRecon {
	return &SessionRecon{sessions: make(map[SessionKey]*TCPSession), halfOpen: make(map[Endpoint]map[SessionKey]struct{}), pressureReported: make(map[Endpoint]bool), HalfOpenThreshold: 20}
}

// Record remains a convenience API for callers that do not supply replayable
// timestamps or payload lengths.
func (r *SessionRecon) Record(key FlowKey, flags uint8, seq uint32) []TCPAnomaly {
	return r.RecordAt(key, flags, seq, 0, time.Now()).Anomalies
}

// RecordAt tracks a TCP conversation without treating either endpoint as a
// protected local service. Call RecordAtForLocalDestination from a capture
// pipeline that knows the selected interface addresses when evaluating SYN
// pressure.
func (r *SessionRecon) RecordAt(key FlowKey, flags uint8, seq uint32, payloadLen int, at time.Time) TCPRecordResult {
	return r.recordAtLocked(key, flags, seq, payloadLen, at, false)
}

// RecordAtForLocalDestination tracks a TCP conversation and only accounts a
// SYN as possible service-side pressure when it is directed to a known address
// on the selected local interface. Outbound connection bursts are therefore
// never labeled possible_syn_flood.
func (r *SessionRecon) RecordAtForLocalDestination(key FlowKey, flags uint8, seq uint32, payloadLen int, at time.Time, localIPs map[string]struct{}) TCPRecordResult {
	_, monitoredDestination := localIPs[key.DstIP]
	return r.recordAtLocked(key, flags, seq, payloadLen, at, monitoredDestination)
}

func (r *SessionRecon) recordAtLocked(key FlowKey, flags uint8, seq uint32, payloadLen int, at time.Time, monitorDestination bool) TCPRecordResult {
	if at.IsZero() {
		at = time.Now()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.recordAt(key, flags, seq, payloadLen, at, monitorDestination)
}

func (r *SessionRecon) recordAt(key FlowKey, flags uint8, seq uint32, payloadLen int, at time.Time, monitorDestination bool) TCPRecordResult {
	canonical := CanonicalSessionKey(key)
	src, dst := endpointFromKeySrc(key), endpointFromKeyDst(key)
	syn, ack := flags&tcpFlagSYN != 0, flags&tcpFlagACK != 0
	rst, fin := flags&tcpFlagRST != 0, flags&tcpFlagFIN != 0
	sess, exists := r.sessions[canonical]
	newAttempt := syn && !ack && (!exists || sess.State == StateClosed)
	if newAttempt {
		sess = &TCPSession{Initiator: src, Responder: dst, State: StateSYN, SYNTime: at, LastSeen: at, PressureHalfOpen: monitorDestination, Ranges: make(map[Endpoint][]sequenceRange)}
		r.sessions[canonical] = sess
		if monitorDestination {
			r.addHalfOpen(sess, canonical)
		}
		result := TCPRecordResult{ConnectionAttempt: &ConnectionAttempt{SrcIP: key.SrcIP, SrcPort: key.SrcPort, DstIP: key.DstIP, DstPort: key.DstPort, At: at}}
		result.Anomalies = r.pressureAnomaly(sess, canonical, key)
		// SYN is bookkeeping only; it is not classified as a retransmission.
		return result
	}
	if !exists { // Capture started midstream: track safely but infer no attack.
		sess = &TCPSession{State: StateNew, LastSeen: at, Ranges: make(map[Endpoint][]sequenceRange)}
		r.sessions[canonical] = sess
	}
	sess.LastSeen = at
	result := TCPRecordResult{}

	if syn && ack && sess.State == StateSYN && src == sess.Responder && dst == sess.Initiator {
		sess.State = StateSYNACK
		r.removeHalfOpen(sess, canonical)
	} else if ack && !syn && !rst && !fin && sess.State == StateSYNACK && src == sess.Initiator && dst == sess.Responder {
		sess.State = StateEstablished
	}

	if payloadLen > 0 {
		sess.DataSeen = true
	}
	if sess.State == StateEstablished && payloadLen > 0 && r.recordRange(sess, src, seq, payloadLen, flags) && !sess.RetransmitReported {
		sess.RetransmitReported = true
		result.Anomalies = append(result.Anomalies, TCPAnomaly{Subtype: "tcp_retransmission", Key: key, Count: 1})
	}
	if rst {
		if sess.State == StateEstablished && !sess.ResetReported {
			sess.ResetReported = true
			result.Anomalies = append(result.Anomalies, TCPAnomaly{Subtype: "tcp_reset", Key: key, Count: 1})
		}
		sess.State = StateClosed
		r.removeHalfOpen(sess, canonical)
	} else if fin {
		sess.State = StateClosed
		r.removeHalfOpen(sess, canonical)
	}
	return result
}

// recordRange only reports fully repeated payload ranges. ACK-only and
// partially overlapping/out-of-order segments are deliberately ignored.
func (r *SessionRecon) recordRange(sess *TCPSession, direction Endpoint, seq uint32, payloadLen int, flags uint8) bool {
	if payloadLen <= 0 {
		return false
	}
	end := seq + uint32(payloadLen)
	for _, prior := range sess.Ranges[direction] {
		if prior.start <= seq && prior.end >= end {
			return true
		}
	}
	sess.Ranges[direction] = append(sess.Ranges[direction], sequenceRange{start: seq, end: end})
	return false
}

// Scope pressure by the local destination service. The session key keeps
// source address/ephemeral-port uniqueness, while the scope represents the
// host and port that may be under SYN pressure.
func halfOpenScope(s *TCPSession) Endpoint { return s.Responder }
func (r *SessionRecon) addHalfOpen(s *TCPSession, key SessionKey) {
	scope := halfOpenScope(s)
	if r.halfOpen[scope] == nil {
		r.halfOpen[scope] = make(map[SessionKey]struct{})
	}
	r.halfOpen[scope][key] = struct{}{}
}
func (r *SessionRecon) removeHalfOpen(s *TCPSession, key SessionKey) {
	if !s.PressureHalfOpen {
		return
	}
	scope := halfOpenScope(s)
	delete(r.halfOpen[scope], key)
	if len(r.halfOpen[scope]) == 0 {
		delete(r.halfOpen, scope)
		delete(r.pressureReported, scope)
	}
	s.PressureHalfOpen = false
}
func (r *SessionRecon) pressureAnomaly(s *TCPSession, key SessionKey, flow FlowKey) []TCPAnomaly {
	scope := halfOpenScope(s)
	count := len(r.halfOpen[scope])
	if count >= r.HalfOpenThreshold && !r.pressureReported[scope] {
		r.pressureReported[scope] = true
		return []TCPAnomaly{{Subtype: "possible_syn_flood", Key: flow, Count: count}}
	}
	return nil
}

// ExpireStale bounds memory and half-open accounting. The caller should pass
// a capture/replay-aware cutoff (the pipeline uses 30 seconds).
func (r *SessionRecon) ExpireStale(cutoff time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for key, sess := range r.sessions {
		if sess.LastSeen.Before(cutoff) {
			r.removeHalfOpen(sess, key)
			delete(r.sessions, key)
		}
	}
}

func (r *SessionRecon) ActiveCount() int { r.mu.Lock(); defer r.mu.Unlock(); return len(r.sessions) }
func (r *SessionRecon) HalfOpenCount(src, dst Endpoint) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.halfOpen[dst])
}
