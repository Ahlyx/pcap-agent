# pcap-agent

`pcap-agent` is a local Go program that captures selected network-interface traffic, summarizes packet metadata in memory, and streams those summaries to a browser dashboard over a local WebSocket. It is intended for visibility and investigation, not as a replacement for an IDS, firewall, or endpoint-security product.

Raw packet payloads are not sent in WebSocket messages and the agent does not write capture data to disk. The default capture filter is `tcp or udp or icmp`, and it is installed in libpcap before packets enter the analysis pipeline.

## What it currently does

- Captures TCP, UDP, and ICMP traffic through libpcap/Npcap.
- Lists capture interfaces and can use an explicitly selected interface.
- Streams individual flow observations, DNS query/answer visibility, traffic statistics, and top talkers to a dashboard.
- Tracks TCP conversations and reports informational TCP retransmission or reset observations.
- Identifies periodic **connection-attempt** patterns and possible vertical port scans using conservative heuristics.
- Emits Ethernet MAC vendor lookup information and whether an address is locally administered.
- Counts transport/network protocols; the dashboard highlights flows whose destination ports are in its built-in OT/ICS port list.
- Supports a local WebSocket mode and an opt-in relay mode.

The detection output is heuristic. A periodic connection, retransmission, reset, locally administered MAC, multi-IP MAC mapping, SYN pressure, or possible port scan is not automatically malicious. Normal browsers, cloud clients, VPNs, virtual machines, Wi-Fi privacy features, lossy links, and ordinary service discovery can all create these observations. DNS support is packet/query visibility only; this agent does **not** claim to detect DNS tunneling. The enrichment package is not currently wired into the capture pipeline, so no threat-intelligence lookup is advertised here.

## Supported platforms

The source and release workflow support 64-bit Windows, Linux, and macOS. Capture depends on the platform packet-capture library and permission model:

| Platform | Capture dependency | Typical capture permission |
| --- | --- | --- |
| Windows | [Npcap](https://npcap.com/) | Run an elevated PowerShell or Windows Terminal. |
| Linux | libpcap development package | Root, or a deliberately configured capture capability/group. |
| macOS | System libpcap (or Homebrew libpcap if required by your toolchain) | Run from an administrator-capable account; `sudo` may be required for live capture. |

Go 1.22 or newer and CGO are required to build the capture binary from source. A C compiler and libpcap headers must be available to CGO.

## Windows setup

1. Install Go 1.22+ from [go.dev](https://go.dev/dl/).
2. Install [Npcap](https://npcap.com/). Its default compatibility settings work for most users; install it before running the agent.
3. Open **PowerShell or Windows Terminal as Administrator**. Do not use `sudo` on Windows.
4. Clone, build, select an interface, then start capture:

```powershell
git clone https://github.com/Ahlyx/pcap-agent.git
Set-Location pcap-agent
go build -ldflags="-s -w" -o pcap-agent.exe ./cmd/agent
.\pcap-agent.exe list-interfaces
.\pcap-agent.exe start --interface "<Npcap interface name>"
```

Npcap interface names may be long device paths (for example `\Device\NPF_{...}`). Copy the name printed by `list-interfaces` exactly.

## Linux setup

Install Go 1.22+, a C compiler, and libpcap development headers. On Debian/Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y build-essential libpcap-dev
```

On Fedora/RHEL, use `sudo dnf install gcc libpcap-devel`; on Arch, use `sudo pacman -S base-devel libpcap`.

Then clone and build:

```bash
git clone https://github.com/Ahlyx/pcap-agent.git
cd pcap-agent
go build -ldflags='-s -w' -o pcap-agent ./cmd/agent
sudo ./pcap-agent list-interfaces
sudo ./pcap-agent start --interface eth0
```

Live capture normally requires root privileges. Advanced users may instead grant narrowly scoped capture privileges according to their distribution’s security policy; the agent does not configure those permissions for you.

## macOS setup

Install Go 1.22+. macOS includes libpcap, but a Homebrew installation can help when your compiler cannot find usable headers:

```bash
brew install libpcap
```

Build and run from the repository:

```bash
git clone https://github.com/Ahlyx/pcap-agent.git
cd pcap-agent
go build -ldflags='-s -w' -o pcap-agent ./cmd/agent
sudo ./pcap-agent list-interfaces
sudo ./pcap-agent start --interface en0
```

macOS commonly requires elevated privileges to open a live capture device. If access is denied, rerun only the capture command with `sudo`; confirm that the selected interface is the active Wi-Fi/Ethernet adapter.

## Prebuilt binaries

Tagged releases are configured to publish Windows amd64, Linux amd64, macOS Intel, and macOS Apple Silicon binaries. If a suitable release asset is available, download it from the [latest release](https://github.com/Ahlyx/pcap-agent/releases/latest), unpack it, install the platform capture dependency above, and run the same `list-interfaces` / `start` commands. You do not need Go to use a prebuilt binary.

## Using the agent

### Choose an interface

Always inspect available capture interfaces before relying on auto-selection:

```powershell
# Windows (elevated PowerShell)
.\pcap-agent.exe list-interfaces
```

```bash
# Linux/macOS, where your capture policy requires elevation
sudo ./pcap-agent list-interfaces
```

`start` can select an interface automatically, but automatic selection uses the first non-loopback adapter with an address. On systems with VPN, Hyper-V, VMware, VirtualBox, WSL, containers, or overlays, explicitly pass `--interface` and verify the startup log’s interface description and addresses.

### Start local mode

Local mode is the default. It starts an HTTP/WebSocket listener on the selected port (default `7777`), with WebSocket endpoint **`ws://localhost:7777/ws`** and health endpoint `http://localhost:7777/`. Browser and agent must run on the same machine for the bundled dashboard configuration.

```powershell
# Windows (run from an elevated PowerShell/Terminal)
.\pcap-agent.exe start --interface "<Npcap interface name>"
.\pcap-agent.exe start --interface "<Npcap interface name>" --port 8888
```

```bash
# Linux/macOS
sudo ./pcap-agent start --interface eth0
sudo ./pcap-agent start --interface en0 --port 8888
```

When using a port other than 7777, update the dashboard’s `WS_URL` in `static/app.js` before serving/opening that dashboard.

### Dashboard

The agent serves the local WebSocket and health response; it does not serve the dashboard HTML. The checked-in dashboard is [static/index.html](static/index.html), configured for `ws://localhost:7777/ws`. Open or serve that static file from the same computer after the agent is running. The hosted Ahlyx Labs PCAP page is also intended to connect to the local agent when deployed/configured for it.

The dashboard shows flow observations, DNS query/answer metadata, counters, protocol distribution, and alerts. Alert IDs are stable and duplicate updates modify one rendered row instead of incrementing the unique alert count.

### Relay mode

`--relay` asks for explicit confirmation before requesting a relay session from `https://api.ahlyxlabs.com`. It sends flow metadata to the relay rather than using the local WebSocket, and prints a session-specific dashboard URL. Only use it when you intentionally want this remote relay behavior:

```powershell
.\pcap-agent.exe start --relay --interface "<Npcap interface name>"
```

```bash
sudo ./pcap-agent start --relay --interface eth0
```

## Detection notes

| Observation | Current meaning |
| --- | --- |
| Periodic connection | A local-origin, unique TCP connection attempt repeats to the same destination service at low jitter over a minimum observation period. It is a `notice`, not proof of C2. |
| Possible port scan | One source makes unique initial TCP attempts to at least 15 destination ports on one destination within 10 seconds. It is a `warning`, not a confirmed scan. Horizontal scans are not covered. |
| Possible SYN flood / SYN pressure | A bounded number of unique half-open TCP sessions reaches the configured threshold. SYN retransmissions do not add to that count. |
| TCP retransmission | A repeated TCP data/sequence range; ACK-only packets are ignored. Retransmission is normal on imperfect networks and is informational. |
| TCP reset | A reset observed for a tracked session. It is informational; the agent does not infer RST injection. |
| MAC observation | Vendor lookup plus the locally administered-address bit. Locally administered does not mean spoofed. A MAC with multiple IPv4 addresses is informational only. |
| DNS visibility | Parsed DNS question and available answer metadata. No DNS-tunneling conclusion is made. |

No `critical` alert is generated by a single routine heuristic. Severity is intentionally conservative: `info`, `notice`, and `warning` are not evidence of confirmed compromise.

## Troubleshooting

**No interfaces found** — Verify Npcap is installed on Windows, or libpcap is installed on Linux/macOS. Run the terminal with the capture permissions described above. VPN/VM adapters are often visible even when the physical adapter is not; reinstall/update Npcap if Windows returns no adapters.

**Wrong interface selected** — Run `list-interfaces` and pass the exact name to `start --interface ...`. Auto-selection is intentionally simple and can choose a virtual adapter.

**Permission or capture-open error** — On Windows, reopen PowerShell/Terminal as Administrator. On Linux, run the capture command with `sudo` or arrange your distribution’s libpcap capabilities. On macOS, try the capture command with `sudo` and check macOS privacy/security policy.

**Npcap missing on Windows** — Install Npcap, then close and reopen the elevated terminal. `pcap-agent.exe list-interfaces` should show Npcap adapters. A Go build may succeed without Npcap, but live capture will not.

**Build failure mentioning libpcap or CGO** — Install the platform development headers and a C compiler, then ensure `CGO_ENABLED` is not disabled. Linux needs `libpcap-dev`/`libpcap-devel`; macOS may need Homebrew `libpcap`; Windows source builds need a CGO-compatible toolchain and Npcap SDK/libpcap headers. Prebuilt release binaries avoid the source-build toolchain requirement but still need a capture driver/runtime.

**Dashboard cannot connect** — Start the agent first, confirm `http://localhost:7777/` returns JSON, and make sure the dashboard’s `WS_URL` is `ws://localhost:7777/ws`. For a custom `--port`, change `WS_URL` to the same port. Browser and agent must be on the same machine in local mode; mixed-content browser policy can also block `ws://` from an HTTPS-hosted page unless that deployment handles the local connection appropriately.

## Development

```bash
# Synchronize module metadata when dependencies change.
go mod tidy

# Format, test, inspect, and build.
gofmt -w .
go test ./...
go vet ./...
go build -ldflags='-s -w' -o pcap-agent ./cmd/agent
```

CI installs libpcap on Linux and builds/tests the project. Release CI builds the four platform assets described above when a `v*` tag is pushed.

## Layout

```text
cmd/agent/  Cobra CLI and analysis pipeline
capture/    libpcap/Npcap interface discovery, BPF filtering, capture loop
analyze/    flow, TCP-session, cadence, scan, DNS, MAC, and statistics logic
ws/         local WebSocket hub/server and relay client
static/     browser dashboard assets (not served by the agent)
session/    local session identifier helper
```

## Limitations

- Capturing depends on local driver support and privilege; encrypted protocols are summarized from metadata, not decrypted.
- The default BPF filter excludes non-TCP/UDP/ICMP traffic before analysis.
- Auto interface selection is not default-route aware.
- Flow messages are emitted per observed packet; aggregate flow state is used for counts/statistics.
- The checked-in dashboard does not yet render standalone MAC messages.
- Detection is local, heuristic, and intentionally conservative. Review packet context and endpoint ownership before acting.

## License

[MIT](LICENSE)
