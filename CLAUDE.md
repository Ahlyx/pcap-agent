# CLAUDE.md

## Project
pcap-agent — lightweight Go network capture agent with a real-time browser dashboard. Users run the binary locally, open ahlyxlabs.com/pcap, and see their network traffic live.

**Repo:** https://github.com/Ahlyx/pcap-agent  
**Part of:** Ahlyx Labs platform (https://ahlyxlabs.com)

---

## Commands
```bash
# Install dependencies
go mod tidy

# Build binary
go build -ldflags="-s -w" -o pcap-agent ./cmd/agent

# Run (local mode — default)
./pcap-agent

# Run (specify interface)
./pcap-agent --interface eth0

# Run (relay mode)
./pcap-agent --relay

# Run (specify local WebSocket port)
./pcap-agent --port 7777

# List available network interfaces
./pcap-agent --list-interfaces

# Run tests
go test ./...
```

---

## Architecture

**Agent:** Go binary users download and run locally  
**Capture:** gopacket + libpcap for raw packet capture  
**Analysis:** in-process, runs on captured packets in real time  
**WebSocket:** local server on `localhost:7777` (local mode) or relay via `api.ahlyxlabs.com` (relay mode)  
**Frontend:** lives in Ahlyx Labs repo at `frontend/pcap/` — NOT in this repo  
**Database:** none — no data is persisted by the agent
```
pcap-agent/
├── cmd/agent/
│   ├── main.go         ← entry point, parses CLI flags, starts capture + WS server
│   └── cli.go          ← flag definitions and help text
├── capture/
│   ├── capture.go      ← gopacket/libpcap capture loop
│   ├── interfaces.go   ← list and select network interfaces
│   └── filter.go       ← BPF filter construction
├── analyze/
│   ├── flows.go        ← flow tracking (src/dst/port/protocol/bytes/packets)
│   ├── beaconing.go    ← detect regular-interval connections (C2 indicator)
│   ├── port_scan.go    ← detect single host hitting many ports
│   ├── top_talkers.go  ← rank hosts by bytes/packets
│   ├── dns.go          ← extract and track DNS queries
│   ├── protocols.go    ← protocol breakdown (HTTP/HTTPS/DNS/etc)
│   └── enrichment.go   ← optional enrichment lookups via api.ahlyxlabs.com
├── ws/
│   ├── server.go       ← WebSocket server on localhost:7777
│   ├── hub.go          ← manages connected browser clients
│   └── messages.go     ← JSON message types sent to browser
├── session/
│   └── session.go      ← session ID generation and management
├── tests/
├── go.mod
├── .gitignore
├── .env.example
└── README.md
```

---

## Modes

### Local Mode (default)
```
pcap-agent
→ captures packets on selected interface
→ runs analysis in real time
→ starts WebSocket server on localhost:7777
→ browser connects to ws://localhost:7777
→ zero data leaves the machine
```

### Relay Mode (--relay flag)
```
pcap-agent --relay
→ captures packets on selected interface
→ runs analysis in real time
→ connects to wss://api.ahlyxlabs.com/ws/relay/{session_id}
→ browser connects to same session via ahlyxlabs.com/pcap?session={id}
→ flow metadata (no payloads) transmitted to Ahlyx Labs API
```

**Relay mode warning printed to terminal:**
```
WARNING: relay mode enabled — connection metadata will be transmitted
to api.ahlyxlabs.com. No packet payloads are ever transmitted,
only flow summaries (src IP, dst IP, port, protocol, byte count).
Press ENTER to continue or Ctrl+C to cancel.
```

---

## WebSocket Message Format

All messages sent from agent to browser are JSON with a `type` field:
```json
// New flow
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
}

// Beaconing alert
{
  "type": "alert",
  "alert_type": "beaconing",
  "src": "192.168.1.5",
  "dst": "185.220.101.1",
  "interval_ms": 30000,
  "count": 24,
  "timestamp": "2026-03-15T22:16:52Z"
}

// Port scan alert
{
  "type": "alert",
  "alert_type": "port_scan",
  "src": "192.168.1.100",
  "ports_hit": 142,
  "window_seconds": 10,
  "timestamp": "2026-03-15T22:16:52Z"
}

// DNS query
{
  "type": "dns",
  "src": "192.168.1.5",
  "query": "example.com",
  "record_type": "A",
  "response": "93.184.216.34",
  "timestamp": "2026-03-15T22:16:52Z"
}

// Stats update (sent every 5 seconds)
{
  "type": "stats",
  "total_packets": 1420,
  "total_bytes": 2048000,
  "top_talkers": [...],
  "protocol_breakdown": {...},
  "active_flows": 14,
  "timestamp": "2026-03-15T22:16:52Z"
}

// Enrichment result (when enrichment.go queries Ahlyx Labs API)
{
  "type": "enrichment",
  "ip": "185.220.101.1",
  "verdict": "threat",
  "abuse_score": 100,
  "is_tor": true,
  "timestamp": "2026-03-15T22:16:52Z"
}

// Connection status
{
  "type": "status",
  "mode": "local",
  "interface": "eth0",
  "session_id": "local",
  "capturing": true
}
```

---

## Analysis Logic

### Beaconing Detection (`analyze/beaconing.go`)
- Track connection timestamps per src→dst:port pair
- Calculate intervals between connections
- Flag if: 5+ connections, interval variance < 20%, interval > 5 seconds
- Common C2 beacon intervals: 30s, 60s, 300s, 3600s

### Port Scan Detection (`analyze/port_scan.go`)
- Track unique dst ports per src IP within a sliding 10-second window
- Flag if: single src hits 15+ unique ports in 10 seconds
- Distinguish horizontal scan (one port, many hosts) vs vertical scan (many ports, one host)

### Top Talkers (`analyze/top_talkers.go`)
- Maintain per-IP byte and packet counters
- Update every packet
- Send top 10 by bytes in stats update every 5 seconds

### DNS Tracking (`analyze/dns.go`)
- Parse DNS request/response pairs from UDP port 53
- Track query → response mapping
- Flag: queries to known malicious domains (via enrichment), excessive NXDOMAIN responses, DNS tunneling indicators (long subdomains, high query rate)

### Protocol Breakdown (`analyze/protocols.go`)
- Classify by port: 80=HTTP, 443=HTTPS, 53=DNS, 22=SSH, 21=FTP etc
- Include OT/ICS ports from Ahlyx Labs scanner: 502=Modbus, 102=S7comm, etc
- Unknown ports grouped as "Other"

### Enrichment Integration (`analyze/enrichment.go`)
- On new flow to external IP: check local cache first
- If not cached: POST to `https://api.ahlyxlabs.com/api/v1/ip/{address}`
- Cache result for 1 hour — do not re-query same IP
- Only query public IPs — skip RFC1918/bogon ranges
- Rate limit: max 5 enrichment lookups per minute to avoid hammering the API

---

## Dependencies
```
github.com/google/gopacket     ← packet capture and parsing
github.com/gorilla/websocket   ← WebSocket server
github.com/spf13/cobra         ← CLI flag parsing
```

**libpcap requirement:**
- Linux/Mac: `sudo apt install libpcap-dev` / usually pre-installed on Mac
- Windows: install Npcap from https://npcap.com (free, same as Wireshark uses)

**Root/admin requirement:**
- Linux/Mac: must run with `sudo` for raw packet capture
- Windows: must run as Administrator

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
3. Register routes in `cmd/server/main.go`:
```go
r.Get("/ws/relay/{session_id}", pcaphandlers.HandleRelay)
r.Get("/api/v1/pcap/session", pcaphandlers.NewSession)
```
4. Add rate limiting for relay endpoints
5. Create `frontend/pcap/` in Ahlyx-Labs with the dashboard frontend
6. Add rewrite to `frontend/vercel.json`
7. Add card to `frontend/landing/index.html`
8. Add URL to `frontend/sitemap.xml`
9. Submit new URL in Google Search Console

**The agent binary stays in this repo forever** — it is the downloadable artifact. Only the relay/session backend and the frontend move into Ahlyx Labs.

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
- Do NOT embed API keys in the binary — relay endpoint is unauthenticated by session ID