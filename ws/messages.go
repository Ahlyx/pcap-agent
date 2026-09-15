package ws

import (
	"strings"
	"time"
)

type FlowMessage struct {
	Type      string    `json:"type"`
	SrcIP     string    `json:"src"`
	DstIP     string    `json:"dst"`
	SrcPort   uint16    `json:"src_port"`
	DstPort   uint16    `json:"dst_port"`
	Protocol  string    `json:"protocol"`
	Bytes     uint64    `json:"bytes"`
	Packets   uint64    `json:"packets"`
	Timestamp time.Time `json:"timestamp"`
}

func NewFlowMessage(srcIP, dstIP string, srcPort, dstPort uint16, protocol string, bytes, packets uint64) *FlowMessage {
	return &FlowMessage{Type: "flow", SrcIP: srcIP, DstIP: dstIP, SrcPort: srcPort, DstPort: dstPort, Protocol: protocol, Bytes: bytes, Packets: packets, Timestamp: time.Now()}
}

// AlertSeverity is intentionally ordered from least to most urgent.
type AlertSeverity string

const (
	SeverityInfo     AlertSeverity = "info"
	SeverityNotice   AlertSeverity = "notice"
	SeverityWarning  AlertSeverity = "warning"
	SeverityCritical AlertSeverity = "critical"
)

func (s AlertSeverity) Rank() int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityWarning:
		return 3
	case SeverityNotice:
		return 2
	default:
		return 1
	}
}

// AlertID creates a stable ID from detector identity/evidence fields.
func AlertID(parts ...string) string { return strings.Join(parts, "|") }

// AlertMessage is the normalized schema for all alert-like events.
type AlertMessage struct {
	Type          string        `json:"type"`
	ID            string        `json:"id"`
	AlertType     string        `json:"alert_type"`
	Subtype       string        `json:"subtype,omitempty"`
	Severity      AlertSeverity `json:"severity"`
	Src           string        `json:"src,omitempty"`
	Dst           string        `json:"dst,omitempty"`
	SrcPort       uint16        `json:"src_port,omitempty"`
	DstPort       uint16        `json:"dst_port,omitempty"`
	IntervalMS    *float64      `json:"interval_ms,omitempty"`
	JitterPct     *float64      `json:"jitter_pct,omitempty"`
	Count         int           `json:"count,omitempty"`
	PortsHit      []uint16      `json:"ports_hit,omitempty"`
	WindowSeconds *int          `json:"window_seconds,omitempty"`
	Timestamp     time.Time     `json:"timestamp"`
}

func NewAlertMessage(id, alertType string, severity AlertSeverity, src, dst string, count int) *AlertMessage {
	return &AlertMessage{Type: "alert", ID: id, AlertType: alertType, Severity: severity, Src: src, Dst: dst, Count: count, Timestamp: time.Now()}
}

type DNSMessage struct {
	Type       string    `json:"type"`
	Src        string    `json:"src"`
	Query      string    `json:"query"`
	RecordType string    `json:"record_type"`
	Response   *string   `json:"response,omitempty"`
	Timestamp  time.Time `json:"timestamp"`
}

func NewDNSMessage(src, query, recordType string, response *string) *DNSMessage {
	return &DNSMessage{Type: "dns", Src: src, Query: query, RecordType: recordType, Response: response, Timestamp: time.Now()}
}

type TalkerEntry struct {
	IP    string `json:"ip"`
	Bytes uint64 `json:"bytes"`
}
type StatsMessage struct {
	Type              string            `json:"type"`
	TotalPackets      uint64            `json:"total_packets"`
	TotalBytes        uint64            `json:"total_bytes"`
	TopTalkers        []TalkerEntry     `json:"top_talkers"`
	ProtocolBreakdown map[string]uint64 `json:"protocol_breakdown"`
	ActiveFlows       int               `json:"active_flows"`
	Timestamp         time.Time         `json:"timestamp"`
}

func NewStatsMessage(totalPackets, totalBytes uint64, topTalkers []TalkerEntry, protoBreakdown map[string]uint64, activeFlows int) *StatsMessage {
	return &StatsMessage{Type: "stats", TotalPackets: totalPackets, TotalBytes: totalBytes, TopTalkers: topTalkers, ProtocolBreakdown: protoBreakdown, ActiveFlows: activeFlows, Timestamp: time.Now()}
}

type EnrichmentMessage struct {
	Type       string    `json:"type"`
	IP         string    `json:"ip"`
	Verdict    string    `json:"verdict"`
	AbuseScore *int      `json:"abuse_score,omitempty"`
	IsTor      bool      `json:"is_tor"`
	Timestamp  time.Time `json:"timestamp"`
}

func NewEnrichmentMessage(ip, verdict string, abuseScore *int, isTor bool) *EnrichmentMessage {
	return &EnrichmentMessage{Type: "enrichment", IP: ip, Verdict: verdict, AbuseScore: abuseScore, IsTor: isTor, Timestamp: time.Now()}
}

type MACMessage struct {
	Type                string    `json:"type"`
	MAC                 string    `json:"mac"`
	IP                  string    `json:"ip"`
	Vendor              string    `json:"vendor"`
	LocallyAdministered bool      `json:"locally_administered"`
	Timestamp           time.Time `json:"timestamp"`
}

func NewMACMessage(mac, ip, vendor string, locallyAdministered bool) *MACMessage {
	return &MACMessage{Type: "mac", MAC: mac, IP: ip, Vendor: vendor, LocallyAdministered: locallyAdministered, Timestamp: time.Now()}
}

type StatusMessage struct {
	Type      string `json:"type"`
	Mode      string `json:"mode"`
	Interface string `json:"interface"`
	SessionID string `json:"session_id"`
	Capturing bool   `json:"capturing"`
}

func NewStatusMessage(mode, iface, sessionID string, capturing bool) *StatusMessage {
	return &StatusMessage{Type: "status", Mode: mode, Interface: iface, SessionID: sessionID, Capturing: capturing}
}
