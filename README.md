# pcap-agent

> Real-time network packet capture and threat detection with a live browser dashboard.

**Part of [Ahlyx Labs](https://ahlyxlabs.com) — security tooling platform.**

---

![Go](https://img.shields.io/badge/go-1.22+-00ADD8?logo=go&logoColor=white)
![License](https://img.shields.io/github/license/Ahlyx/pcap-agent)
![CI](https://github.com/Ahlyx/pcap-agent/actions/workflows/ci.yml/badge.svg)
![Release](https://img.shields.io/github/v/release/Ahlyx/pcap-agent)

---

## Dashboard

The browser dashboard shows live packet flows, protocol breakdown, top talkers by volume, beaconing and port scan alerts, and threat enrichment results for public IPs — all streaming in real time as traffic passes through your interface.

```
pcap-agent v0.1.0
interface:  ens33
mode:       local
session:    b3690d89
websocket:  ws://localhost:7777/ws
dashboard:  open ahlyxlabs.com/pcap in your browser
press Ctrl+C to stop
```

---

## How it works

Download the binary and run it locally with `sudo`. The agent opens a raw socket on your chosen interface, captures packets, and runs analysis entirely on your machine — no cloud required. Results are streamed to a WebSocket server on `localhost:7777`.

Open [ahlyxlabs.com/pcap](https://ahlyxlabs.com/pcap) in your browser and it connects automatically. The dashboard updates in real time as traffic flows. No raw packet data leaves your machine — the agent transmits flow metadata only (src IP, dst IP, port, protocol, byte count).

---

## Prerequisites

### Linux
```bash
sudo apt-get install -y libpcap-dev
# Must run with sudo for raw packet capture
```

### macOS
```bash
brew install libpcap
# Must run with sudo for raw packet capture
```

### Windows

1. Download and install **Npcap** from [https://npcap.com](https://npcap.com) (free — same as Wireshark uses)
2. Must run as **Administrator**

---

## Installation

### Option 1 — Download binary (recommended)

Download the latest release from [github.com/Ahlyx/pcap-agent/releases/latest](https://github.com/Ahlyx/pcap-agent/releases/latest):

| Platform | File |
|---|---|
| Linux (amd64) | `pcap-agent-linux-amd64` |
| Windows (amd64) | `pcap-agent-windows-amd64.exe` |
| macOS (Intel) | `pcap-agent-darwin-amd64` |
| macOS (Apple Silicon) | `pcap-agent-darwin-arm64` |

### Option 2 — Build from source

```bash
# Requires Go 1.22+ and libpcap-dev
git clone https://github.com/Ahlyx/pcap-agent.git
cd pcap-agent
go build -o pcap-agent ./cmd/agent
```

---

## Usage

```bash
# List available interfaces
sudo ./pcap-agent list-interfaces

# Start with auto-detected interface (local mode)
sudo ./pcap-agent start

# Start on a specific interface
sudo ./pcap-agent start --interface eth0

# Start on a custom WebSocket port
sudo ./pcap-agent start --port 8888

# Start in relay mode (streams via api.ahlyxlabs.com)
sudo ./pcap-agent start --relay
```

Then open [ahlyxlabs.com/pcap](https://ahlyxlabs.com/pcap) in your browser.

---

## Modes

### Local mode (default)

- WebSocket server runs on `localhost:7777`
- Browser connects directly to your machine
- Zero data leaves your machine
- Both browser and agent must be on the same machine

### Relay mode (`--relay`)

- Agent connects outbound to `api.ahlyxlabs.com`
- Browser connects to the same session from anywhere
- Only flow metadata transmitted — no packet payloads, ever
- Useful when the agent runs on a server or VM you are monitoring remotely
- Prints a warning and requires confirmation before starting:

```
WARNING: relay mode enabled — connection metadata will be transmitted
to api.ahlyxlabs.com. No packet payloads are ever transmitted,
only flow summaries (src IP, dst IP, port, protocol, byte count).
Press ENTER to continue or Ctrl+C to cancel.
```

---

## Detection

| Detection | Description |
|---|---|
| Beaconing | Regular-interval outbound connections — C2 indicator |
| Port scanning | Single host hitting 15+ unique ports in 10 seconds |
| DNS tunneling | Excessively long subdomains, high NXDOMAIN rate |
| OT/ICS exposure | Modbus, S7comm, DNP3, EtherNet/IP, BACnet and 9 more |
| Threat enrichment | Auto-lookup of public IPs via Ahlyx Labs enrichment API |

**Beaconing** is flagged when a src→dst pair has 5+ connections with interval variance below 20%. Common C2 intervals (30 s, 60 s, 300 s, 3600 s) are caught reliably.

**Enrichment** lookups hit `api.ahlyxlabs.com/api/v1/ip/{address}` for each new public IP seen. Results are cached for 1 hour. Private and bogon ranges are never queried. Rate-limited to 5 lookups per minute.

---

## OT/ICS Port Coverage

Traffic on any of the following ports is flagged with a ⚠ OT marker in the flow table and included in the protocol breakdown:

| Protocol | Port |
|---|---|
| Modbus | 502 |
| Siemens S7comm | 102 |
| EtherNet/IP | 44818 |
| EtherNet/IP (alt) | 2222 |
| OPC-UA | 4840 |
| DNP3 | 20000 |
| BACnet | 47808 |
| OMRON FINS | 9600 |
| PCWorx | 1962 |
| GE SRTP | 18245 |
| Emerson DeltaV | 4000 |
| FOUNDATION Fieldbus (SM) | 1089 |
| FOUNDATION Fieldbus (FMS) | 1090 |
| FOUNDATION Fieldbus | 1091 |

---

## Privacy

- **Local mode:** no data leaves your machine under any circumstances
- **Relay mode:** flow summaries only — src IP, dst IP, port, protocol, byte count — no payloads
- **Enrichment lookups:** public IPs only, results cached locally for 1 hour
- **Nothing is stored to disk** — the agent is fully stateless

---

## Development

```bash
# Install dependencies
go mod tidy

# Run tests
go test ./...

# Build all platforms (handled by GitHub Actions on tag push)
git tag v0.x.x
git push origin v0.x.x
```

CI runs on every push to `main`. Release binaries for all four platforms are built automatically when a `v*` tag is pushed.

---

## Architecture

```
pcap-agent/
├── cmd/agent/
│   ├── main.go         entry point
│   └── cli.go          cobra commands: start, list-interfaces
├── capture/
│   ├── capture.go      gopacket/libpcap capture loop
│   ├── interfaces.go   interface enumeration and auto-selection
│   └── filter.go       BPF filter construction
├── analyze/
│   ├── flows.go        flow table with idle-timeout expiry
│   ├── beaconing.go    regular-interval connection detection
│   ├── port_scan.go    sliding-window distinct-port counter
│   ├── top_talkers.go  per-IP byte counter, TopN ranking
│   ├── dns.go          DNS query/response extraction
│   ├── protocols.go    per-protocol packet counter
│   └── enrichment.go   public IP enrichment with local cache
├── ws/
│   ├── server.go       HTTP server, /ws upgrade handler, /health
│   ├── hub.go          client registry, broadcast channel, drop-on-slow
│   └── messages.go     JSON message structs (flow, alert, dns, stats, enrichment, status)
├── session/
│   └── session.go      8-char hex session ID via crypto/rand
└── tests/
```

**Dependencies:** `github.com/google/gopacket` · `github.com/gorilla/websocket` · `github.com/spf13/cobra`

---

## License

[MIT](LICENSE)
