package main

import (
	"net"
	"testing"

	"github.com/Ahlyx/pcap-agent/analyze"
	"github.com/Ahlyx/pcap-agent/ws"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func tcpPacket(t *testing.T, src, dst string, srcPort, dstPort uint16, syn, ack bool) gopacket.Packet {
	t.Helper()
	eth := layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}
	ip := layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: net.ParseIP(src).To4(), DstIP: net.ParseIP(dst).To4()}
	tcp := layers.TCP{SrcPort: layers.TCPPort(srcPort), DstPort: layers.TCPPort(dstPort), Seq: 1, SYN: syn, ACK: ack}
	if err := tcp.SetNetworkLayerForChecksum(&ip); err != nil {
		t.Fatal(err)
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, &eth, &ip, &tcp); err != nil {
		t.Fatal(err)
	}
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func TestPipelineOnlyFeedsInitialSynAttemptsAndKnownLocalCadence(t *testing.T) {
	flows := analyze.NewFlowTable(0)
	talkers, protos := analyze.NewTalkerCounter(), analyze.NewProtocolCounter()
	beaconCfg := analyze.DefaultBeaconingConfig()
	beaconCfg.MinConnections = 2
	beaconCfg.MinSpan = 0
	beaconing := analyze.NewBeaconingDetector(beaconCfg)
	portCfg := analyze.DefaultPortScanConfig()
	portCfg.PortThreshold = 2
	portScan := analyze.NewPortScanDetector(portCfg)
	macs, recon := analyze.NewMACTracker(), analyze.NewSessionRecon()
	alerts := ws.NewAlertEmitter(func(interface{}) {}, 0)
	var packets, bytes uint64
	process := func(packet gopacket.Packet) {
		processPacket(packet, func(interface{}) {}, alerts, map[string]struct{}{"10.0.0.2": {}}, flows, talkers, protos, beaconing, portScan, macs, recon, &packets, &bytes)
	}

	// Two remote SYNs and a remote ACK are not outbound cadence evidence.
	process(tcpPacket(t, "203.0.113.2", "10.0.0.2", 50000, 443, true, false))
	process(tcpPacket(t, "203.0.113.2", "10.0.0.2", 50001, 443, true, false))
	process(tcpPacket(t, "203.0.113.2", "10.0.0.2", 50002, 8443, false, true))
	if got := beaconing.Check(); len(got) != 0 {
		t.Fatalf("remote traffic became outbound cadence evidence: %#v", got)
	}

	// ACK/data-like packets on a new destination port are not scan attempts.
	process(tcpPacket(t, "10.0.0.2", "203.0.113.2", 40000, 443, true, false))
	process(tcpPacket(t, "10.0.0.2", "203.0.113.2", 40000, 8443, false, true))
	if got := portScan.Check(); len(got) != 0 {
		t.Fatalf("non-SYN packet added scan evidence: %#v", got)
	}
	process(tcpPacket(t, "10.0.0.2", "203.0.113.2", 40001, 8443, true, false))
	if got := portScan.Check(); len(got) != 1 {
		t.Fatalf("two unique SYN attempts did not produce scan evidence: %#v", got)
	}
}
