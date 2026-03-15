package capture

import (
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// Config holds pcap capture parameters.
type Config struct {
	Interface   string
	Filter      string
	Snaplen     int32
	Promiscuous bool
}

// Capture manages an active pcap handle.
type Capture struct {
	config Config
	handle *pcap.Handle
	done   chan struct{}
}

// New opens a pcap handle on the given interface and applies the BPF filter.
func New(cfg Config) (*Capture, error) {
	handle, err := pcap.OpenLive(cfg.Interface, cfg.Snaplen, cfg.Promiscuous, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("capture: open %s: %w", cfg.Interface, err)
	}

	if cfg.Filter != "" {
		if err := handle.SetBPFFilter(cfg.Filter); err != nil {
			handle.Close()
			return nil, fmt.Errorf("capture: set BPF filter %q: %w", cfg.Filter, err)
		}
	}

	return &Capture{
		config: cfg,
		handle: handle,
		done:   make(chan struct{}),
	}, nil
}

// Start reads packets from the handle and sends them to out.
// It runs in its own goroutine and exits when Stop is called or on error.
func (c *Capture) Start(out chan<- gopacket.Packet) {
	go func() {
		src := gopacket.NewPacketSource(c.handle, c.handle.LinkType())
		src.DecodeOptions = gopacket.Default

		packets := src.Packets()
		for {
			select {
			case <-c.done:
				return
			case pkt, ok := <-packets:
				if !ok {
					log.Println("capture: packet source closed")
					return
				}
				select {
				case out <- pkt:
				case <-c.done:
					return
				}
			}
		}
	}()
}

// Stop signals the capture goroutine to exit and closes the pcap handle.
func (c *Capture) Stop() {
	select {
	case <-c.done:
		// Already stopped.
	default:
		close(c.done)
	}
	c.handle.Close()
}
