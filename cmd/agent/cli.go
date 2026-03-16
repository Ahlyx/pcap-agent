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
	flagMode      string
)

func buildRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "pcap-agent",
		Short: "Network traffic capture agent with browser streaming",
	}

	root.PersistentFlags().StringVarP(&flagInterface, "interface", "i", "", "Network interface to capture on (default: auto-detect)")
	root.PersistentFlags().IntVarP(&flagPort, "port", "p", 7777, "WebSocket server port")
	root.PersistentFlags().StringVarP(&flagMode, "mode", "m", "local", "Mode: local or relay")

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

	sess := session.NewSession(flagMode, iface)
	log.Println(sess)

	hub := ws.NewHub()
	go hub.Run()

	srv := ws.NewServer(flagPort, hub)

	// Broadcast initial status.
	hub.Broadcast(ws.NewStatusMessage(flagMode, iface, sess.ID, false))

	// Start WebSocket server in background.
	go func() {
		if err := srv.Start(); err != nil {
			log.Fatalf("ws server: %v", err)
		}
	}()

	// Wait briefly so the server is up before capturing.
	time.Sleep(100 * time.Millisecond)

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

	hub.Broadcast(ws.NewStatusMessage(flagMode, iface, sess.ID, true))
	log.Printf("capturing on %s  (ws://localhost:%d)", iface, flagPort)

	pktCh := make(chan gopacket.Packet, 1024)
	cap.Start(pktCh)

	return runAnalysisPipeline(hub, pktCh)
}

func runAnalysisPipeline(hub *ws.Hub, pktCh <-chan gopacket.Packet) error {
	flows := analyze.NewFlowTable(5 * time.Minute)
	talkers := analyze.NewTalkerCounter()
	protos := analyze.NewProtocolCounter()
	beaconing := analyze.NewBeaconingDetector(analyze.DefaultBeaconingConfig())
	portScan := analyze.NewPortScanDetector(analyze.DefaultPortScanConfig())

	statsTicker := time.NewTicker(5 * time.Second)
	alertTicker := time.NewTicker(10 * time.Second)
	defer statsTicker.Stop()
	defer alertTicker.Stop()

	var totalPackets, totalBytes uint64

	for {
		select {
		case pkt, ok := <-pktCh:
			if !ok {
				return nil
			}
			processPacket(pkt, hub, flows, talkers, protos, beaconing, portScan, &totalPackets, &totalBytes)

		case <-statsTicker.C:
			sendStats(hub, totalPackets, totalBytes, talkers, protos, flows)

		case <-alertTicker.C:
			checkAlerts(hub, beaconing, portScan)
		}
	}
}

func processPacket(
	pkt gopacket.Packet,
	hub *ws.Hub,
	flows *analyze.FlowTable,
	talkers *analyze.TalkerCounter,
	protos *analyze.ProtocolCounter,
	beaconing *analyze.BeaconingDetector,
	portScan *analyze.PortScanDetector,
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

	var srcPort, dstPort uint16
	var proto string

	if tcp, ok := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP); ok && tcp != nil {
		srcPort = uint16(tcp.SrcPort)
		dstPort = uint16(tcp.DstPort)
		proto = "TCP"
		beaconing.Record(srcIP, dstIP)
		portScan.Record(srcIP, dstIP, dstPort)
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
	hub.Broadcast(ws.NewFlowMessage(srcIP, dstIP, srcPort, dstPort, proto, pktLen, 1))

	// Parse DNS.
	if evt := analyze.ParseDNS(pkt); evt != nil {
		var resp *string
		if evt.Response != "" {
			r := evt.Response
			resp = &r
		}
		hub.Broadcast(ws.NewDNSMessage(evt.Src, evt.Query, evt.RecordType, resp))
	}
}

func sendStats(hub *ws.Hub, totalPackets, totalBytes uint64, talkers *analyze.TalkerCounter, protos *analyze.ProtocolCounter, flows *analyze.FlowTable) {
	top := talkers.TopN(10)
	talkerEntries := make([]ws.TalkerEntry, len(top))
	for i, t := range top {
		talkerEntries[i] = ws.TalkerEntry{IP: t.IP, Bytes: t.Bytes}
	}
	hub.Broadcast(ws.NewStatsMessage(totalPackets, totalBytes, talkerEntries, protos.Snapshot(), flows.ActiveCount()))
}

func checkAlerts(hub *ws.Hub, beaconing *analyze.BeaconingDetector, portScan *analyze.PortScanDetector) {
	for _, r := range beaconing.Check() {
		msg := ws.NewAlertMessage("beaconing", r.Src, r.Dst, r.Count)
		iv := r.IntervalMS
		msg.IntervalMS = &iv
		hub.Broadcast(msg)
	}
	for _, r := range portScan.Check() {
		msg := ws.NewAlertMessage("port_scan", r.Src, r.Dst, len(r.PortsHit))
		msg.PortsHit = r.PortsHit
		w := int(r.Window.Seconds())
		msg.WindowSeconds = &w
		hub.Broadcast(msg)
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
