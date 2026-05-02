package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/Ahlyx/pcap-agent/analyze"
	"github.com/Ahlyx/pcap-agent/capture"
	"github.com/Ahlyx/pcap-agent/session"
	"github.com/Ahlyx/pcap-agent/ws"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/spf13/cobra"
)

var (
	flagInterface string
	flagPort      int
	flagRelay     bool
)

func buildRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "pcap-agent",
		Short: "Network traffic capture agent with browser streaming",
	}

	root.PersistentFlags().StringVarP(&flagInterface, "interface", "i", "", "Network interface to capture on (default: auto-detect)")
	root.PersistentFlags().IntVarP(&flagPort, "port", "p", 7777, "WebSocket server port")
	root.PersistentFlags().BoolVar(&flagRelay, "relay", false, "Stream via api.ahlyxlabs.com relay instead of local WebSocket")

	root.AddCommand(buildStartCmd())
	root.AddCommand(buildListCmd())
	return root
}

func buildStartCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: "Start capturing and stream to browser",
		RunE:  runStart,
	}
}

func buildListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list-interfaces",
		Short: "Print available network interfaces",
		RunE: func(cmd *cobra.Command, args []string) error {
			ifaces, err := capture.ListInterfaces()
			if err != nil {
				return err
			}
			capture.PrintInterfaces(ifaces)
			return nil
		},
	}
}

func runStart(cmd *cobra.Command, args []string) error {
	iface := flagInterface
	if iface == "" {
		auto, err := capture.SelectDefault()
		if err != nil {
			return fmt.Errorf("interface auto-detect: %w", err)
		}
		iface = auto
		log.Printf("auto-selected interface: %s", iface)
	}

	cfg := capture.Config{
		Interface:   iface,
		Filter:      capture.DefaultFilter(),
		Snaplen:     65535,
		Promiscuous: true,
	}
	cap, err := capture.New(cfg)
	if err != nil {
		return fmt.Errorf("open capture: %w", err)
	}
	defer cap.Stop()

	pktCh := make(chan gopacket.Packet, 1024)

	if flagRelay {
		fmt.Println("WARNING: relay mode enabled — connection metadata will be transmitted")
		fmt.Println("to api.ahlyxlabs.com. No packet payloads are ever transmitted,")
		fmt.Println("only flow summaries (src IP, dst IP, port, protocol, byte count).")
		fmt.Println("Press ENTER to continue or Ctrl+C to cancel.")
		fmt.Scanln()

		relayClient, err := ws.NewRelayClient("https://api.ahlyxlabs.com")
		if err != nil {
			return fmt.Errorf("relay: %w", err)
		}
		defer relayClient.Close()

		fmt.Printf("pcap-agent v0.2.0\n")
		fmt.Printf("interface:  %s\n", iface)
		fmt.Printf("mode:       relay\n")
		fmt.Printf("session:    %s\n", relayClient.SessionID())
		fmt.Printf("dashboard:  ahlyxlabs.com/pcap?session=%s\n", relayClient.SessionID())
		fmt.Printf("press Ctrl+C to stop\n")

		cap.Start(pktCh)
		return runAnalysisPipeline(relayClient.Broadcast, pktCh)
	}

	// Local mode.
	sess := session.NewSession("local", iface)

	hub := ws.NewHub()
	go hub.Run()

	srv := ws.NewServer(flagPort, hub)

	hub.Broadcast(ws.NewStatusMessage("local", iface, sess.ID, false))

	go func() {
		if err := srv.Start(); err != nil {
			log.Fatalf("ws server: %v", err)
		}
	}()

	time.Sleep(100 * time.Millisecond)

	hub.Broadcast(ws.NewStatusMessage("local", iface, sess.ID, true))
	log.Printf("capturing on %s  (ws://localhost:%d)", iface, flagPort)

	cap.Start(pktCh)
	return runAnalysisPipeline(hub.Broadcast, pktCh)
}

func runAnalysisPipeline(broadcast func(interface{}), pktCh <-chan gopacket.Packet) error {
	flows := analyze.NewFlowTable(5 * time.Minute)
	talkers := analyze.NewTalkerCounter()
	protos := analyze.NewProtocolCounter()
	beaconing := analyze.NewBeaconingDetector(analyze.DefaultBeaconingConfig())
	portScan := analyze.NewPortScanDetector(analyze.DefaultPortScanConfig())
	macTracker := analyze.NewMACTracker()
	sessionRecon := analyze.NewSessionRecon()

	statsTicker := time.NewTicker(5 * time.Second)
	alertTicker := time.NewTicker(10 * time.Second)
	expireTicker := time.NewTicker(30 * time.Second)
	defer statsTicker.Stop()
	defer alertTicker.Stop()
	defer expireTicker.Stop()

	log.Printf("pipeline started")
	var totalPackets, totalBytes uint64

	for {
		select {
		case pkt, ok := <-pktCh:
			if !ok {
				return nil
			}
			processPacket(pkt, broadcast, flows, talkers, protos, beaconing, portScan, macTracker, sessionRecon, &totalPackets, &totalBytes)

		case <-statsTicker.C:
			sendStats(broadcast, totalPackets, totalBytes, talkers, protos, flows)

		case <-alertTicker.C:
			checkAlerts(broadcast, beaconing, portScan)

		case <-expireTicker.C:
			sessionRecon.ExpireStale(time.Now().Add(-30 * time.Second))
		}
	}
}

func processPacket(
	pkt gopacket.Packet,
	broadcast func(interface{}),
	flows *analyze.FlowTable,
	talkers *analyze.TalkerCounter,
	protos *analyze.ProtocolCounter,
	beaconing *analyze.BeaconingDetector,
	portScan *analyze.PortScanDetector,
	macTracker *analyze.MACTracker,
	sessionRecon *analyze.SessionRecon,
	totalPackets, totalBytes *uint64,
) {
	pktLen := uint64(len(pkt.Data()))
	*totalPackets++
	*totalBytes += pktLen

	protos.Record(pkt)

	netLayer := pkt.NetworkLayer()
	if netLayer == nil {
		return
	}
	srcIP, dstIP := splitEndpointsFromFlow(netLayer.NetworkFlow())
	talkers.Record(srcIP, pktLen)

	// L2 MAC intelligence.
	if eth, ok := pkt.Layer(layers.LayerTypeEthernet).(*layers.Ethernet); ok && eth != nil {
		mac := eth.SrcMAC.String()
		intel, first := macTracker.Record(mac, srcIP)
		if first {
			broadcast(ws.NewMACMessage(intel.MAC, intel.IP, intel.Vendor, intel.Spoofed))
		}
		if ips := macTracker.MultihomeCheck(mac); len(ips) > 1 {
			msg := ws.NewAlertMessage("mac_multihome", mac, srcIP, len(ips))
			broadcast(msg)
		}
	}

	var srcPort, dstPort uint16
	var proto string

	if tcp, ok := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP); ok && tcp != nil {
		srcPort = uint16(tcp.SrcPort)
		dstPort = uint16(tcp.DstPort)
		proto = "TCP"
		beaconing.Record(srcIP, dstIP)
		portScan.Record(srcIP, dstIP, dstPort)

		var flags uint8
		if tcp.SYN {
			flags |= 0x02
		}
		if tcp.ACK {
			flags |= 0x10
		}
		if tcp.RST {
			flags |= 0x04
		}
		if tcp.FIN {
			flags |= 0x01
		}
		tcpKey := analyze.FlowKey{
			SrcIP:   srcIP,
			DstIP:   dstIP,
			SrcPort: srcPort,
			DstPort: dstPort,
			Proto:   proto,
		}
		for _, anomaly := range sessionRecon.Record(tcpKey, flags, uint32(tcp.Seq)) {
			broadcast(ws.NewTCPAnomalyMessage(anomaly.Subtype, anomaly.Key.SrcIP, anomaly.Key.DstIP, anomaly.Key.DstPort, 1))
		}
	} else if udp, ok := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP); ok && udp != nil {
		srcPort = uint16(udp.SrcPort)
		dstPort = uint16(udp.DstPort)
		proto = "UDP"
	} else {
		proto = "ICMP"
	}

	key := analyze.FlowKey{
		SrcIP:   srcIP,
		DstIP:   dstIP,
		SrcPort: srcPort,
		DstPort: dstPort,
		Proto:   proto,
	}
	flows.Update(key, pktLen)

	// Emit flow message.
	broadcast(ws.NewFlowMessage(srcIP, dstIP, srcPort, dstPort, proto, pktLen, 1))

	// Parse DNS.
	if evt := analyze.ParseDNS(pkt); evt != nil {
		var resp *string
		if evt.Response != "" {
			r := evt.Response
			resp = &r
		}
		broadcast(ws.NewDNSMessage(evt.Src, evt.Query, evt.RecordType, resp))
	}
}

func sendStats(broadcast func(interface{}), totalPackets, totalBytes uint64, talkers *analyze.TalkerCounter, protos *analyze.ProtocolCounter, flows *analyze.FlowTable) {
	top := talkers.TopN(10)
	talkerEntries := make([]ws.TalkerEntry, len(top))
	for i, t := range top {
		talkerEntries[i] = ws.TalkerEntry{IP: t.IP, Bytes: t.Bytes}
	}
	broadcast(ws.NewStatsMessage(totalPackets, totalBytes, talkerEntries, protos.Snapshot(), flows.ActiveCount()))
}

func checkAlerts(broadcast func(interface{}), beaconing *analyze.BeaconingDetector, portScan *analyze.PortScanDetector) {
	for _, r := range beaconing.Check() {
		msg := ws.NewAlertMessage("beaconing", r.Src, r.Dst, r.Count)
		iv := r.IntervalMS
		msg.IntervalMS = &iv
		broadcast(msg)
	}
	for _, r := range portScan.Check() {
		msg := ws.NewAlertMessage("port_scan", r.Src, r.Dst, len(r.PortsHit))
		msg.PortsHit = r.PortsHit
		w := int(r.Window.Seconds())
		msg.WindowSeconds = &w
		broadcast(msg)
	}
}

func splitEndpointsFromFlow(flow gopacket.Flow) (src, dst string) {
	src = flow.Src().String()
	dst = flow.Dst().String()
	return
}

func Execute() {
	if err := buildRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
