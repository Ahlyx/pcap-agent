package analyze

import (
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// DNSEvent holds the parsed result of a single DNS packet.
type DNSEvent struct {
	Src        string
	Query      string
	RecordType string
	Response   string // empty for pure queries
}

// ParseDNS extracts DNS information from a packet.
// Returns nil if the packet contains no DNS layer.
func ParseDNS(pkt gopacket.Packet) *DNSEvent {
	dnsLayer := pkt.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return nil
	}
	dns, ok := dnsLayer.(*layers.DNS)
	if !ok || len(dns.Questions) == 0 {
		return nil
	}

	q := dns.Questions[0]
	event := &DNSEvent{
		Query:      string(q.Name),
		RecordType: q.Type.String(),
	}

	// Extract source IP.
	if net := pkt.NetworkLayer(); net != nil {
		event.Src, _ = splitEndpoints(net.NetworkFlow().String())
	}

	// Collect answers if this is a response.
	if dns.QR && len(dns.Answers) > 0 {
		var answers []string
		for _, a := range dns.Answers {
			if a.IP != nil {
				answers = append(answers, a.IP.String())
			} else if len(a.CNAME) > 0 {
				answers = append(answers, string(a.CNAME))
			}
		}
		event.Response = strings.Join(answers, ",")
	}

	return event
}

// splitEndpoints splits a gopacket flow string "src->dst" into its parts.
func splitEndpoints(flow string) (src, dst string) {
	parts := strings.SplitN(flow, "->", 2)
	if len(parts) == 2 {
		return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	}
	return flow, ""
}
