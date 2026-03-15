package capture

import (
	"errors"
	"fmt"

	"github.com/google/gopacket/pcap"
)

// Interface describes a network interface available for capture.
type Interface struct {
	Name        string
	Description string
	Addresses   []string
	IsLoopback  bool
}

// String returns a formatted single-line description.
func (i Interface) String() string {
	return fmt.Sprintf("%-16s  loopback=%-5v  addrs=%v  desc=%s",
		i.Name, i.IsLoopback, i.Addresses, i.Description)
}

// ListInterfaces returns all network interfaces visible to libpcap.
func ListInterfaces() ([]Interface, error) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("capture: list interfaces: %w", err)
	}

	result := make([]Interface, 0, len(devs))
	for _, d := range devs {
		iface := Interface{
			Name:        d.Name,
			Description: d.Description,
			IsLoopback:  (d.Flags & 0x1) != 0,
		}
		for _, addr := range d.Addresses {
			if addr.IP != nil {
				iface.Addresses = append(iface.Addresses, addr.IP.String())
			}
		}
		result = append(result, iface)
	}
	return result, nil
}

// SelectDefault returns the first non-loopback interface that has at least one IP address.
func SelectDefault() (string, error) {
	ifaces, err := ListInterfaces()
	if err != nil {
		return "", err
	}
	for _, i := range ifaces {
		if !i.IsLoopback && len(i.Addresses) > 0 {
			return i.Name, nil
		}
	}
	return "", errors.New("capture: no suitable non-loopback interface found")
}

// PrintInterfaces prints a formatted table of available interfaces.
func PrintInterfaces(ifaces []Interface) {
	fmt.Printf("%-4s  %-16s  %-8s  %-24s  %s\n", "#", "Name", "Loopback", "Addresses", "Description")
	fmt.Printf("%-4s  %-16s  %-8s  %-24s  %s\n", "---", "----", "--------", "---------", "-----------")
	for idx, i := range ifaces {
		addrs := "-"
		if len(i.Addresses) > 0 {
			addrs = i.Addresses[0]
			if len(i.Addresses) > 1 {
				addrs += fmt.Sprintf(" (+%d)", len(i.Addresses)-1)
			}
		}
		fmt.Printf("%-4d  %-16s  %-8v  %-24s  %s\n",
			idx+1, i.Name, i.IsLoopback, addrs, i.Description)
	}
}
