package analyze

import (
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ProtocolCounter tracks per-protocol byte/packet counts.
type ProtocolCounter struct {
	mu     sync.RWMutex
	counts map[string]uint64
}

// NewProtocolCounter creates an empty counter.
func NewProtocolCounter() *ProtocolCounter {
	return &ProtocolCounter{counts: make(map[string]uint64)}
}

// Record extracts the transport/network protocol from pkt and increments its counter.
func (pc *ProtocolCounter) Record(pkt gopacket.Packet) {
	proto := protocolName(pkt)
	pc.mu.Lock()
	pc.counts[proto]++
	pc.mu.Unlock()
}

// Snapshot returns a copy of the current counts.
func (pc *ProtocolCounter) Snapshot() map[string]uint64 {
	pc.mu.RLock()
	defer pc.mu.RUnlock()
	out := make(map[string]uint64, len(pc.counts))
	for k, v := range pc.counts {
		out[k] = v
	}
	return out
}

// protocolName returns a human-readable protocol label for a packet.
func protocolName(pkt gopacket.Packet) string {
	if pkt.Layer(layers.LayerTypeTCP) != nil {
		return "TCP"
	}
	if pkt.Layer(layers.LayerTypeUDP) != nil {
		return "UDP"
	}
	if pkt.Layer(layers.LayerTypeICMPv4) != nil {
		return "ICMPv4"
	}
	if pkt.Layer(layers.LayerTypeICMPv6) != nil {
		return "ICMPv6"
	}
	if pkt.Layer(layers.LayerTypeIPv6) != nil {
		return "IPv6-other"
	}
	if pkt.Layer(layers.LayerTypeIPv4) != nil {
		return "IPv4-other"
	}
	return "other"
}
