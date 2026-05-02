package analyze

import (
	"net"
	"sync"
)

// ouiMap is a static lookup table of the top 30 OUI prefixes (first 3 octets).
var ouiMap = map[string]string{
	"00:0c:29": "VMware",
	"00:50:56": "VMware",
	"00:05:69": "VMware",
	"08:00:27": "VirtualBox",
	"0a:00:27": "VirtualBox",
	"00:1a:4b": "Cisco",
	"00:0d:60": "Cisco",
	"00:1b:54": "Cisco",
	"00:13:10": "Cisco",
	"3c:5a:b4": "Apple",
	"a4:c3:f0": "Apple",
	"f8:ff:c2": "Apple",
	"dc:a9:04": "Apple",
	"b8:27:eb": "Raspberry Pi",
	"dc:a6:32": "Raspberry Pi",
	"e4:5f:01": "Raspberry Pi",
	"00:1a:11": "Google",
	"f4:f5:d8": "Google",
	"00:16:3e": "Xen",
	"02:42:ac": "Docker",
	"52:54:00": "QEMU/KVM",
	"00:15:5d": "Microsoft Hyper-V",
	"00:03:ff": "Microsoft",
	"00:1c:42": "Parallels",
	"00:26:b9": "Dell",
	"d4:be:d9": "Dell",
	"f8:bc:12": "HP",
	"3c:d9:2b": "HP",
	"fc:3f:db": "Intel",
	"8c:8d:28": "Intel",
}

// MACIntel holds intelligence derived for a single MAC address.
type MACIntel struct {
	MAC     string
	IP      string
	Vendor  string
	Spoofed bool
}

// MACTracker records L2 MAC addresses and their associated IPs.
type MACTracker struct {
	mu      sync.Mutex
	seen    map[string]bool
	ips     map[string][]string // MAC → distinct IPs observed
	alerted map[string]bool     // MAC → multihome alert already fired
}

// NewMACTracker creates a ready-to-use MACTracker.
func NewMACTracker() *MACTracker {
	return &MACTracker{
		seen:    make(map[string]bool),
		ips:     make(map[string][]string),
		alerted: make(map[string]bool),
	}
}

// Record notes a (mac, ip) observation. Returns the derived MACIntel and true
// only on the first observation of this MAC (false on all subsequent calls).
func (t *MACTracker) Record(mac, ip string) (MACIntel, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	first := !t.seen[mac]
	t.seen[mac] = true

	found := false
	for _, existing := range t.ips[mac] {
		if existing == ip {
			found = true
			break
		}
	}
	if !found {
		t.ips[mac] = append(t.ips[mac], ip)
	}

	return MACIntel{
		MAC:     mac,
		IP:      ip,
		Vendor:  VendorLookup(mac),
		Spoofed: IsSpoofed(mac),
	}, first
}

// IsSpoofed returns true if the locally administered bit (0x02) is set in the
// first octet of the MAC, indicating a non-burned-in address.
func IsSpoofed(mac string) bool {
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) == 0 {
		return false
	}
	return hw[0]&0x02 != 0
}

// VendorLookup returns the vendor name for a MAC by matching its OUI prefix
// (first 8 characters, e.g. "00:0c:29"), or "Unknown" if not in the table.
func VendorLookup(mac string) string {
	if len(mac) < 8 {
		return "Unknown"
	}
	if vendor, ok := ouiMap[mac[:8]]; ok {
		return vendor
	}
	return "Unknown"
}

// MultihomeCheck returns the distinct IPv4 addresses observed for mac the
// first time 2+ are detected, so the caller can emit exactly one alert per
// MAC per session. Returns nil on all subsequent calls for the same MAC, and
// also returns nil when fewer than 2 IPv4 addresses have been seen.
// Link-local IPv6 (fe80::/10) and all other IPv6 addresses are excluded.
func (t *MACTracker) MultihomeCheck(mac string) []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.alerted[mac] {
		return nil
	}
	var out []string
	for _, ip := range t.ips[mac] {
		if net.ParseIP(ip).To4() != nil {
			out = append(out, ip)
		}
	}
	if len(out) < 2 {
		return nil
	}
	t.alerted[mac] = true
	return out
}
