package analyze

import (
	"fmt"
	"reflect"
	"testing"
	"time"
)

func tcpKey(src string, srcPort uint16, dst string, dstPort uint16) FlowKey {
	return FlowKey{SrcIP: src, SrcPort: srcPort, DstIP: dst, DstPort: dstPort, Proto: "TCP"}
}

func established(t *testing.T, r *SessionRecon, key FlowKey, at time.Time) {
	t.Helper()
	if got := r.RecordAt(key, tcpFlagSYN, 1, 0, at); got.ConnectionAttempt == nil {
		t.Fatal("initial SYN did not produce attempt")
	}
	reverse := tcpKey(key.DstIP, key.DstPort, key.SrcIP, key.SrcPort)
	r.RecordAt(reverse, tcpFlagSYN|tcpFlagACK, 10, 0, at.Add(time.Millisecond))
	r.RecordAt(key, tcpFlagACK, 2, 0, at.Add(2*time.Millisecond))
}

func TestConnectionAttemptsAreInitialSYNsOnly(t *testing.T) {
	r, at := NewSessionRecon(), time.Unix(100, 0)
	key := tcpKey("10.0.0.2", 50000, "198.51.100.2", 443)
	if got := r.RecordAt(key, tcpFlagSYN, 1, 0, at); got.ConnectionAttempt == nil {
		t.Fatal("missing initial attempt")
	}
	if got := r.RecordAt(key, tcpFlagSYN, 1, 0, at.Add(time.Second)); got.ConnectionAttempt != nil {
		t.Fatal("SYN retransmit became a second attempt")
	}
	if got := r.RecordAt(tcpKey("10.0.0.2", 50001, "198.51.100.2", 443), tcpFlagSYN, 1, 0, at); got.ConnectionAttempt == nil {
		t.Fatal("new source port was not a new attempt")
	}
	for _, flags := range []uint8{tcpFlagSYN | tcpFlagACK, tcpFlagACK, tcpFlagFIN, tcpFlagRST} {
		if got := r.RecordAt(tcpKey("198.51.100.2", 443, "10.0.0.2", 50000), flags, 2, 0, at); got.ConnectionAttempt != nil {
			t.Fatalf("flags %x became attempt", flags)
		}
	}
}

func TestBeaconingUsesServiceAndPrunesStaleHistory(t *testing.T) {
	cfg := DefaultBeaconingConfig()
	cfg.MinSpan = time.Minute
	d := NewBeaconingDetector(cfg)
	at := time.Unix(100, 0)
	for i := 0; i < 6; i++ {
		d.RecordAt("10.0.0.2", "203.0.113.2", 443, at.Add(time.Duration(i)*12*time.Second))
	}
	results := d.CheckAt(at.Add(61 * time.Second))
	if len(results) != 1 || results[0].DstPort != 443 || results[0].Count != 6 {
		t.Fatalf("unexpected periodic results: %#v", results)
	}
	// Separate service histories and stale histories must not continue alerting.
	d.RecordAt("10.0.0.2", "203.0.113.2", 8443, at)
	if got := d.CheckAt(at.Add(61 * time.Second)); len(got) != 1 {
		t.Fatalf("different service merged into cadence history: %#v", got)
	}
	if got := d.CheckAt(at.Add(11 * time.Minute)); len(got) != 0 {
		t.Fatalf("stale cadence remained: %#v", got)
	}
}

func TestPortScanWindowThresholdAndOrdering(t *testing.T) {
	d := NewPortScanDetector(DefaultPortScanConfig())
	at := time.Unix(100, 0)
	for p := uint16(14); p >= 1; p-- {
		d.RecordAt("10.0.0.2", "203.0.113.2", p, at)
	}
	if got := d.CheckAt(at.Add(time.Second)); len(got) != 0 {
		t.Fatalf("14 ports triggered: %#v", got)
	}
	d.RecordAt("10.0.0.2", "203.0.113.2", 15, at.Add(time.Second))
	got := d.CheckAt(at.Add(2 * time.Second))
	if len(got) != 1 {
		t.Fatalf("15 ports did not trigger: %#v", got)
	}
	if !reflect.DeepEqual(got[0].PortsHit, []uint16{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}) {
		t.Fatalf("ports not sorted: %v", got[0].PortsHit)
	}
	if got := d.CheckAt(at.Add(11 * time.Second)); len(got) != 0 {
		t.Fatalf("stale scan state remained: %#v", got)
	}
}

func TestBidirectionalSessionAndRetransmissionSemantics(t *testing.T) {
	at, r := time.Unix(100, 0), NewSessionRecon()
	key := tcpKey("10.0.0.2", 50000, "203.0.113.2", 443)
	established(t, r, key, at)
	if r.ActiveCount() != 1 {
		t.Fatalf("handshake was not one session: %d", r.ActiveCount())
	}
	if got := r.RecordAt(key, tcpFlagACK, 100, 0, at.Add(time.Second)).Anomalies; len(got) != 0 {
		t.Fatalf("ACK-only packet labeled retransmit: %#v", got)
	}
	if got := r.RecordAt(key, tcpFlagACK, 100, 10, at.Add(2*time.Second)).Anomalies; len(got) != 0 {
		t.Fatalf("first payload labeled retransmit: %#v", got)
	}
	if got := r.RecordAt(key, tcpFlagACK, 110, 10, at.Add(3*time.Second)).Anomalies; len(got) != 0 {
		t.Fatalf("non-overlapping payload labeled retransmit: %#v", got)
	}
	got := r.RecordAt(key, tcpFlagACK, 100, 10, at.Add(4*time.Second)).Anomalies
	if len(got) != 1 || got[0].Subtype != "tcp_retransmission" {
		t.Fatalf("repeated payload not reported: %#v", got)
	}
	if got := r.RecordAt(key, tcpFlagACK, 100, 10, at.Add(5*time.Second)).Anomalies; len(got) != 0 {
		t.Fatalf("repeated retransmit emitted repeatedly: %#v", got)
	}
	reverse := tcpKey(key.DstIP, key.DstPort, key.SrcIP, key.SrcPort)
	if got := r.RecordAt(reverse, tcpFlagRST, 1, 0, at.Add(6*time.Second)).Anomalies; len(got) != 1 || got[0].Subtype != "tcp_reset" {
		t.Fatalf("normal reset should be informational: %#v", got)
	}
	if r.ActiveCount() != 1 {
		t.Fatal("reverse RST created a second session")
	}
}

func TestOutboundConnectionBurstIsNotSynFloodPressure(t *testing.T) {
	at, r := time.Unix(100, 0), NewSessionRecon()
	local := "2001:db8:10::5"
	remote := "2606:4700:4700::1111"
	localIPs := map[string]struct{}{local: {}}
	for i := 0; i < r.HalfOpenThreshold; i++ {
		key := tcpKey(local, uint16(50000+i), remote, 443)
		if got := r.RecordAtForLocalDestination(key, tcpFlagSYN, 1, 0, at.Add(time.Duration(i)*time.Millisecond), localIPs).Anomalies; len(got) != 0 {
			t.Fatalf("normal outbound HTTPS burst became SYN flood evidence: %#v", got)
		}
	}
	if got := r.HalfOpenCount(Endpoint{}, Endpoint{IP: remote, Port: 443}); got != 0 {
		t.Fatalf("outbound attempts entered protected-service pressure accounting: %d", got)
	}
}

func TestInboundSynPressureTargetsMonitoredService(t *testing.T) {
	at, r := time.Unix(100, 0), NewSessionRecon()
	local := "2001:db8:20::10"
	localIPs := map[string]struct{}{local: {}}
	for i := 0; i < r.HalfOpenThreshold; i++ {
		key := tcpKey(fmt.Sprintf("2001:db8:30::%x", i+1), uint16(40000+i), local, 443)
		got := r.RecordAtForLocalDestination(key, tcpFlagSYN, 1, 0, at.Add(time.Duration(i)*time.Millisecond), localIPs).Anomalies
		if i < r.HalfOpenThreshold-1 && len(got) != 0 {
			t.Fatalf("pressure alerted before threshold: %#v", got)
		}
		if i == r.HalfOpenThreshold-1 && (len(got) != 1 || got[0].Subtype != "possible_syn_flood" || got[0].Count != r.HalfOpenThreshold) {
			t.Fatalf("inbound monitored-service pressure did not alert at threshold: %#v", got)
		}
	}
	if got := r.HalfOpenCount(Endpoint{}, Endpoint{IP: local, Port: 443}); got != r.HalfOpenThreshold {
		t.Fatalf("protected service half-open count = %d, want %d", got, r.HalfOpenThreshold)
	}
}

func TestSynRetransmissionsDoNotInflateProtectedPressure(t *testing.T) {
	at, r := time.Unix(100, 0), NewSessionRecon()
	r.HalfOpenThreshold = 2
	local := "10.0.0.2"
	localIPs := map[string]struct{}{local: {}}
	key := tcpKey("203.0.113.2", 50001, local, 443)
	for i := 0; i < 20; i++ {
		if got := r.RecordAtForLocalDestination(key, tcpFlagSYN, 1, 0, at.Add(time.Duration(i)*time.Millisecond), localIPs).Anomalies; len(got) != 0 {
			t.Fatalf("SYN retransmission produced pressure alert: %#v", got)
		}
	}
	if got := r.HalfOpenCount(Endpoint{}, endpointFromKeyDst(key)); got != 1 {
		t.Fatalf("SYN retransmissions inflated half-open count: %d", got)
	}
}

func TestCompletedHandshakeRemovesProtectedHalfOpen(t *testing.T) {
	at, r := time.Unix(100, 0), NewSessionRecon()
	local := "10.0.0.2"
	localIPs := map[string]struct{}{local: {}}
	key := tcpKey("203.0.113.2", 50001, local, 443)
	r.RecordAtForLocalDestination(key, tcpFlagSYN, 1, 0, at, localIPs)
	reverse := tcpKey(key.DstIP, key.DstPort, key.SrcIP, key.SrcPort)
	r.RecordAtForLocalDestination(reverse, tcpFlagSYN|tcpFlagACK, 2, 0, at.Add(time.Millisecond), localIPs)
	r.RecordAtForLocalDestination(key, tcpFlagACK, 2, 0, at.Add(2*time.Millisecond), localIPs)
	if got := r.HalfOpenCount(Endpoint{}, endpointFromKeyDst(key)); got != 0 {
		t.Fatalf("completed handshake left protected session half-open: %d", got)
	}
}

func TestStaleProtectedHalfOpenExpires(t *testing.T) {
	at, r := time.Unix(100, 0), NewSessionRecon()
	local := "10.0.0.2"
	localIPs := map[string]struct{}{local: {}}
	key := tcpKey("203.0.113.2", 50001, local, 443)
	r.RecordAtForLocalDestination(key, tcpFlagSYN, 1, 0, at, localIPs)
	r.ExpireStale(at.Add(time.Second))
	if got := r.HalfOpenCount(Endpoint{}, endpointFromKeyDst(key)); got != 0 {
		t.Fatalf("stale protected half-open session remained: %d", got)
	}
}

func TestCaptureBeginningMidstreamDoesNotCreateSynPressure(t *testing.T) {
	at, r := time.Unix(100, 0), NewSessionRecon()
	r.HalfOpenThreshold = 1
	local := "10.0.0.2"
	localIPs := map[string]struct{}{local: {}}
	midstream := tcpKey("203.0.113.2", 50001, local, 443)
	if got := r.RecordAtForLocalDestination(midstream, tcpFlagACK, 100, 10, at, localIPs).Anomalies; len(got) != 0 {
		t.Fatalf("midstream data inferred SYN flood: %#v", got)
	}
	if got := r.RecordAtForLocalDestination(midstream, tcpFlagRST, 100, 0, at.Add(time.Millisecond), localIPs).Anomalies; len(got) != 0 {
		t.Fatalf("midstream reset inferred SYN flood: %#v", got)
	}
}

func TestFlowTableIsBidirectional(t *testing.T) {
	at := time.Unix(100, 0)
	ft := NewFlowTable(time.Hour)
	a := tcpKey("10.0.0.2", 50000, "203.0.113.2", 443)
	b := tcpKey(a.DstIP, a.DstPort, a.SrcIP, a.SrcPort)
	ft.UpdateAt(a, 10, at)
	ft.UpdateAt(b, 20, at.Add(time.Second))
	if ft.ActiveCount() != 1 {
		t.Fatalf("directions counted separately: %d", ft.ActiveCount())
	}
	rec := ft.Snapshot()[0]
	if rec.Bytes != 30 || rec.Packets != 2 || rec.BytesAB != 10 || rec.BytesBA != 20 {
		t.Fatalf("incorrect bidirectional aggregate: %#v", rec)
	}
	ft.ExpireAt(at.Add(2 * time.Hour))
	if ft.ActiveCount() != 0 {
		t.Fatal("canonical flow did not expire")
	}
}
