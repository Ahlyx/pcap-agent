package ws

import "time"

// FlowMessage represents a network flow between two endpoints.
type FlowMessage struct {
	Type      string    `json:"type"`
	SrcIP     string    `json:"src_ip"`
	DstIP     string    `json:"dst_ip"`
	SrcPort   uint16    `json:"src_port"`
	DstPort   uint16    `json:"dst_port"`
	Protocol  string    `json:"protocol"`
	Bytes     uint64    `json:"bytes"`
	Packets   uint64    `json:"packets"`
	Timestamp time.Time `json:"timestamp"`
}

func NewFlowMessage(srcIP, dstIP string, srcPort, dstPort uint16, protocol string, bytes, packets uint64) *FlowMessage {
	return &FlowMessage{
		Type:      "flow",
		SrcIP:     srcIP,
		DstIP:     dstIP,
		SrcPort:   srcPort,
		DstPort:   dstPort,
		Protocol:  protocol,
		Bytes:     bytes,
		Packets:   packets,
		Timestamp: time.Now(),
	}
}

// AlertMessage represents a detected anomaly such as beaconing or port scan.
type AlertMessage struct {
	Type          string    `json:"type"`
	AlertType     string    `json:"alert_type"`
	Src           string    `json:"src"`
	Dst           string    `json:"dst"`
	IntervalMS    *float64  `json:"interval_ms,omitempty"`
	Count         int       `json:"count"`
	PortsHit      []uint16  `json:"ports_hit,omitempty"`
	WindowSeconds *int      `json:"window_seconds,omitempty"`
	Timestamp     time.Time `json:"timestamp"`
}

func NewAlertMessage(alertType, src, dst string, count int) *AlertMessage {
	return &AlertMessage{
		Type:      "alert",
		AlertType: alertType,
		Src:       src,
		Dst:       dst,
		Count:     count,
		Timestamp: time.Now(),
	}
}

// DNSMessage represents a captured DNS query/response.
type DNSMessage struct {
	Type       string    `json:"type"`
	Src        string    `json:"src"`
	Query      string    `json:"query"`
	RecordType string    `json:"record_type"`
	Response   *string   `json:"response,omitempty"`
	Timestamp  time.Time `json:"timestamp"`
}

func NewDNSMessage(src, query, recordType string, response *string) *DNSMessage {
	return &DNSMessage{
		Type:       "dns",
		Src:        src,
		Query:      query,
		RecordType: recordType,
		Response:   response,
		Timestamp:  time.Now(),
	}
}

// TalkerEntry is a single entry in the top-talkers list.
type TalkerEntry struct {
	IP    string `json:"ip"`
	Bytes uint64 `json:"bytes"`
}

// StatsMessage reports aggregate capture statistics.
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
	return &StatsMessage{
		Type:              "stats",
		TotalPackets:      totalPackets,
		TotalBytes:        totalBytes,
		TopTalkers:        topTalkers,
		ProtocolBreakdown: protoBreakdown,
		ActiveFlows:       activeFlows,
		Timestamp:         time.Now(),
	}
}

// EnrichmentMessage carries threat intelligence for an IP address.
type EnrichmentMessage struct {
	Type       string    `json:"type"`
	IP         string    `json:"ip"`
	Verdict    string    `json:"verdict"`
	AbuseScore *int      `json:"abuse_score,omitempty"`
	IsTor      bool      `json:"is_tor"`
	Timestamp  time.Time `json:"timestamp"`
}

func NewEnrichmentMessage(ip, verdict string, abuseScore *int, isTor bool) *EnrichmentMessage {
	return &EnrichmentMessage{
		Type:       "enrichment",
		IP:         ip,
		Verdict:    verdict,
		AbuseScore: abuseScore,
		IsTor:      isTor,
		Timestamp:  time.Now(),
	}
}

// StatusMessage describes the current agent state.
type StatusMessage struct {
	Type      string `json:"type"`
	Mode      string `json:"mode"`
	Interface string `json:"interface"`
	SessionID string `json:"session_id"`
	Capturing bool   `json:"capturing"`
}

func NewStatusMessage(mode, iface, sessionID string, capturing bool) *StatusMessage {
	return &StatusMessage{
		Type:      "status",
		Mode:      mode,
		Interface: iface,
		SessionID: sessionID,
		Capturing: capturing,
	}
}
