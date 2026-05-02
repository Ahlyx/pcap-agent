# CLAUDE.md

## Project
pcap-agent — lightweight Go network capture agent with a real-time browser dashboard. Users run the binary locally, open ahlyxlabs.com/pcap, and see their network traffic live.

**Repo:** https://github.com/Ahlyx/pcap-agent  
**Part of:** Ahlyx Labs platform (https://ahlyxlabs.com)

---

## Commands
```bashInstall dependencies
go mod tidyBuild binary
go build -ldflags="-s -w" -o pcap-agent ./cmd/agentRun (local mode — default)
./pcap-agentRun (specify interface)
./pcap-agent --interface eth0Run (relay mode)
./pcap-agent --relayRun (specify local WebSocket port)
./pcap-agent --port 7777List available network interfaces
./pcap-agent --list-interfacesRun tests
go test ./...

---

## Architecture

**Agent:** Go binary users download and run locally  
**Capture:** gopacket + libpcap for raw packet capture  
**Analysis:** in-process, runs on captured packets in real time  
**WebSocket:** local server on `localhost:7777` (local mode) or relay via `api.ahlyxlabs.com` (relay mode)  
**Frontend:** lives in Ahlyx Labs repo at `frontend/pcap/` — NOT in this repo  
**Database:** none — no data is persisted by the agentpcap-agent/
├── cmd/agent/
│   ├── main.go         ← entry point
│   └── cli.go          ← cobra commands, runAnalysisPipeline, processPacket
├── capture/
│   ├── capture.go      ← gopacket/libpcap capture loop
│   ├── interfaces.go   ← interface enumeration and auto-selection
│   └── filter.go       ← BPF filter construction
├── analyze/
│   ├── flows.go        ← flow table with idle-timeout expiry
│   ├── beaconing.go    ← regular-interval connection detection
│   ├── port_scan.go    ← sliding-window distinct-port counter
│   ├── top_talkers.go  ← per-IP byte counter, TopN ranking
│   ├── dns.go          ← DNS query/response extraction
│   ├── protocols.go    ← per-protocol packet counter
│   ├── enrichment.go   ← public IP enrichment with local cache
│   ├── mac.go          ← L2: MAC address intel, OUI lookup, spoof detection [NEW]
│   └── session_recon.go ← L4: TCP session reconstruction, anomaly detection [NEW]
├── ws/
│   ├── server.go       ← HTTP server, /ws upgrade handler, /health
│   ├── hub.go          ← client registry, broadcast channel, drop-on-slow
│   └── messages.go     ← JSON message structs
├── session/
│   └── session.go      ← session ID generation
└── tests/

---

## Modes

### Local Mode (default)pcap-agent
→ captures packets on selected interface
→ runs analysis in real time
→ starts WebSocket server on localhost:7777
→ browser connects to ws://localhost:7777
→ zero data leaves the machine

### Relay Mode (--relay flag)pcap-agent --relay
→ captures packets on selected interface
→ runs analysis in real time
→ connects to wss://api.ahlyxlabs.com/ws/relay/{session_id}
→ browser connects to same session via ahlyxlabs.com/pcap?session={id}
→ flow metadata (no payloads) transmitted to Ahlyx Labs API

---

## WebSocket Message Format

All messages sent from agent to browser are JSON with a `type` field:

```json// New flow
{
"type": "flow",
"src": "192.168.1.5",
"dst": "8.8.8.8",
"src_port": 54321,
"dst_port": 443,
"protocol": "HTTPS",
"bytes": 1240,
"packets": 12,
"timestamp": "2026-03-15T22:16:52Z"
}// Beaconing alert
{
"type": "alert",
"alert_type": "beaconing",
"src": "192.168.1.5",
"dst": "185.220.101.1",
"interval_ms": 30000,
"count": 24,
"timestamp": "2026-03-15T22:16:52Z"
}// Port scan alert
{
"type": "alert",
"alert_type": "port_scan",
"src": "192.168.1.100",
"ports_hit": 142,
"window_seconds": 10,
"timestamp": "2026-03-15T22:16:52Z"
}// TCP anomaly alert [NEW]
{
"type": "alert",
"alert_type": "tcp_anomaly",
"subtype": "syn_flood|retransmit|rst_injection",
"src": "192.168.1.5",
"dst": "10.0.0.1",
"dst_port": 80,
"count": 12,
"timestamp": "2026-03-15T22:16:52Z"
}// MAC intel event [NEW]
{
"type": "mac",
"mac": "00:0c:29:bb:48:a1",
"ip": "192.168.1.5",
"vendor": "VMware, Inc.",
"spoofed": false,
"timestamp": "2026-03-15T22:16:52Z"
}// DNS query
{
"type": "dns",
"src": "192.168.1.5",
"query": "example.com",
"record_type": "A",
"response": "93.184.216.34",
"timestamp": "2026-03-15T22:16:52Z"
}// Stats update (sent every 5 seconds)
{
"type": "stats",
"total_packets": 1420,
"total_bytes": 2048000,
"top_talkers": [...],
"protocol_breakdown": {...},
"active_flows": 14,
"timestamp": "2026-03-15T22:16:52Z"
}// Enrichment result
{
"type": "enrichment",
"ip": "185.220.101.1",
"verdict": "threat",
"abuse_score": 100,
"is_tor": true,
"timestamp": "2026-03-15T22:16:52Z"
}// Connection status
{
"type": "status",
"mode": "local",
"interface": "eth0",
"session_id": "local",
"capturing": true
}

---

## Analysis Logic

### Beaconing Detection (`analyze/beaconing.go`)
- Track connection timestamps per src→dst:port pair
- Calculate intervals between connections
- Flag if: 5+ connections, interval variance < 20%, interval > 5 seconds

### Port Scan Detection (`analyze/port_scan.go`)
- Track unique dst ports per src IP within a sliding 60-second window
- Flag if: single src hits 15+ unique ports in window

### Top Talkers (`analyze/top_talkers.go`)
- Maintain per-IP byte and packet counters
- Send top 10 by bytes in stats update every 5 seconds

### DNS Tracking (`analyze/dns.go`)
- Parse DNS request/response pairs from UDP port 53
- Flag excessive NXDOMAIN responses and long subdomains (tunneling indicators)

### Protocol Breakdown (`analyze/protocols.go`)
- Classify by port: 80=HTTP, 443=HTTPS, 53=DNS, 22=SSH, 21=FTP etc
- Include OT/ICS ports: 502=Modbus, 102=S7comm, etc
- Unknown ports grouped as "Other"

### Enrichment Integration (`analyze/enrichment.go`)
- On new flow to external IP: check local cache first
- Cache result for 1 hour — never re-query same IP
- Only query public IPs — skip RFC1918/bogon ranges
- Rate limit: max 5 lookups per minute

### MAC Intelligence (`analyze/mac.go`) [NEW]
- Extract Ethernet layer from every packet via gopacket `layers.LayerTypeEthernet`
- OUI lookup against embedded static table (top ~1000 vendors, no external calls)
- Spoof detection: check locally administered bit (bit 1 of first octet)
- Deduplicate — emit `mac` message only on first time a MAC is seen
- Track MAC→IP mapping; flag if same MAC appears on multiple IPs

### TCP Session Reconstruction (`analyze/session_recon.go`) [NEW]
- Track TCP state per FlowKey (reuse existing FlowKey from flows.go)
- State machine: SYN → SYN-ACK → ESTABLISHED → FIN/RST → CLOSED
- Detect SYN flood: src sends 20+ SYNs to same dst with no SYN-ACK within 5s
- Detect retransmits: same seq number seen 3+ times on a flow
- Detect RST injection: RST received after data transfer (post-ESTABLISHED)
- Emit `alert` with `alert_type: "tcp_anomaly"` and subtype field
- Expire stale half-open sessions after 30 seconds

---

## Dependenciesgithub.com/google/gopacket     ← packet capture and parsing
github.com/gorilla/websocket   ← WebSocket server
github.com/spf13/cobra         ← CLI flag parsing

No new dependencies required for either new feature — gopacket already
exposes the Ethernet and TCP layers needed.

---

## Security Notes

- Never transmit raw packet payloads — flow metadata only
- Never log or store packet data to disk
- Enrichment lookups are fire-and-forget — no user data stored
- In relay mode: session IDs are random UUIDs, expire after 1 hour of inactivity
- BPF filters can be used to exclude sensitive traffic before capture

---

## Porting to Ahlyx Labs

When the agent is working and stable, port the backend session/relay logic into Ahlyx Labs:

1. Copy `capture/`, `analyze/`, `ws/`, `session/` into `internal/pcap/` in Ahlyx-Labs repo
2. Add `internal/pcap/handlers/` with chi route handlers for relay WebSocket endpoint
3. Register routes in `cmd/server/main.go`
4. Add rate limiting for relay endpoints
5. Create `frontend/pcap/` in Ahlyx-Labs with the dashboard frontend

**The agent binary stays in this repo forever.**

---

## Rules

- Never transmit or store raw packet payloads — metadata and flow summaries only
- BPF filter must be applied before any packet reaches analysis code
- Enrichment lookups must respect RFC1918/bogon ranges — never query private IPs
- Enrichment cache must be checked before every API call — no duplicate lookups
- WebSocket messages must always include a `type` field
- Stats updates must be sent on a ticker, never per-packet (too noisy)
- Agent must handle interface going down gracefully — reconnect or exit cleanly
- Relay mode requires explicit user confirmation before starting
- Do NOT store any data to disk — agent is stateless
- Do NOT embed API keys in the binary
- MAC messages must be deduplicated — emit once per unique MAC address seen
- TCP session state must be expired to prevent unbounded memory growth