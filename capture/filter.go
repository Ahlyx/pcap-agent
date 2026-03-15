package capture

import (
	"fmt"
	"strings"
)

// FilterOptions controls BPF filter generation.
type FilterOptions struct {
	ExcludeLoopback bool
	ProtocolsOnly   []string
	ExcludePorts    []int
	IncludePorts    []int
}

// DefaultFilter returns a sensible BPF expression for most use cases.
func DefaultFilter() string {
	return "tcp or udp or icmp"
}

// BuildFilter assembles a BPF expression from FilterOptions.
// It always returns a valid (non-empty) BPF string.
func BuildFilter(opts FilterOptions) string {
	var parts []string

	// Protocol restriction.
	if len(opts.ProtocolsOnly) > 0 {
		protoExprs := make([]string, len(opts.ProtocolsOnly))
		for i, p := range opts.ProtocolsOnly {
			protoExprs[i] = strings.ToLower(p)
		}
		parts = append(parts, "("+strings.Join(protoExprs, " or ")+")")
	} else {
		parts = append(parts, "(tcp or udp or icmp)")
	}

	// Include only specific ports.
	if len(opts.IncludePorts) > 0 {
		portExprs := make([]string, len(opts.IncludePorts))
		for i, p := range opts.IncludePorts {
			portExprs[i] = fmt.Sprintf("port %d", p)
		}
		parts = append(parts, "("+strings.Join(portExprs, " or ")+")")
	}

	// Exclude loopback traffic.
	if opts.ExcludeLoopback {
		parts = append(parts, "not loopback")
	}

	// Exclude specific ports.
	for _, p := range opts.ExcludePorts {
		parts = append(parts, fmt.Sprintf("not port %d", p))
	}

	if len(parts) == 0 {
		return DefaultFilter()
	}
	return strings.Join(parts, " and ")
}
