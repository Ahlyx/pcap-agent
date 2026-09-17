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
4. Clone, build, then start capture. `start` automatically selects the first non-loopback interface with an address:

```powershell
git clone https://github.com/Ahlyx/pcap-agent.git
Set-Location pcap-agent
go build -ldflags="-s -w" -o pcap-agent.exe ./cmd/agent
.\pcap-agent start
```

For VPN, VM, container, or other multi-adapter systems, choose an interface explicitly:

```powershell
.\pcap-agent list-interfaces
.\pcap-agent start --interface "<Npcap interface name>"
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

Tagged releases publish one archive for each supported platform. Download the appropriate archive from the [latest release](https://github.com/Ahlyx/pcap-agent/releases/latest), extract it, install the platform capture dependency above, and run the normal `start` command. You do not need Go to use a prebuilt binary.

| Platform | Release asset | Extracted executable |
| --- | --- | --- |
| Windows | `pcap-agent-windows.zip` | `pcap-agent.exe` |
| Linux | `pcap-agent-linux.tar.gz` | `pcap-agent` |
| macOS — Intel | `pcap-agent-macos-intel.tar.gz` | `pcap-agent` |
| macOS — Apple Silicon | `pcap-agent-macos-apple-silicon.tar.gz` | `pcap-agent` |

After extraction, open a terminal in the extracted folder. Automatic interface selection is the normal workflow:

```powershell
# Windows (elevated PowerShell)
.\pcap-agent start
```

```bash
# Linux/macOS (use sudo only when your capture policy requires elevation)
./pcap-agent start
```

The Linux and macOS archives preserve the executable bit. If you extracted them with a tool that removed it, restore it once with `chmod +x pcap-agent`.

### Verify a downloaded release

Every release includes a `SHA256SUMS` asset covering every downloadable
archive. Download it from the same official GitHub release as the archive.

```bash
# Linux/macOS: run in the folder containing SHA256SUMS and the archive.
sha256sum -c SHA256SUMS
```

```powershell
# Windows: compare the archive hash with its matching SHA256SUMS entry.
(Get-FileHash .\pcap-agent-windows.zip -Algorithm SHA256).Hash
```

GitHub Actions also publishes build provenance attestations for release
archives. With GitHub CLI installed, an optional provenance check is:

```bash
gh attestation verify pcap-agent-linux.tar.gz --repo Ahlyx/pcap-agent
```

Checksums confirm the downloaded archive matches the release manifest;
provenance verification checks the recorded GitHub Actions build origin. These
artifacts are not represented as a separate code-signing certificate.

## Using the agent

### Automatic interface selection

`start` is the normal workflow and automatically selects the first non-loopback interface with an address:

```powershell
# Windows (elevated PowerShell)
.\pcap-agent start
```

```bash
# Linux/macOS
./pcap-agent start
```

### Advanced: choose an interface

On systems with VPN, Hyper-V, VMware, VirtualBox, WSL, containers, or overlays, inspect the available interfaces and select one explicitly:

```powershell
# Windows (elevated PowerShell)
.\pcap-agent list-interfaces
```

```bash
# Linux/macOS
./pcap-agent list-interfaces
```

Automatic selection is intentionally simple. When selecting an interface explicitly, verify the startup log’s interface description and addresses.

### Start local mode

Local mode is the default. It starts an HTTP/WebSocket listener on `127.0.0.1` at the selected port (default `7777`), with WebSocket endpoint **`ws://localhost:7777/ws`** and health endpoint `http://localhost:7777/`. No LAN or WAN interface listens by default, and browser WebSocket connections are accepted only from the Ahlyx Labs dashboard or an explicit loopback development origin.

```powershell
# Windows (run from an elevated PowerShell/Terminal)
.\pcap-agent start
.\pcap-agent start --port 8888
```

```bash
# Linux/macOS (add sudo only when your capture policy requires elevation)
./pcap-agent start --interface eth0
./pcap-agent start --interface en0 --port 8888
```

Keep the default port when using the hosted Ahlyx Labs PCAP page. For a custom port, use a WebSocket client or dashboard configured for the matching `ws://localhost:<port>/ws` endpoint.

`--listen` is an advanced option for a deliberate alternate bind address. A non-loopback value prints a warning because it makes captured metadata reachable to other hosts; use it only with an appropriate access-control layer on a trusted network.

### Dashboard

The agent serves the local WebSocket and health response; it does not bundle or serve the production frontend. The production web UI is maintained separately in [Ahlyx-Labs](https://github.com/Ahlyx/Ahlyx-Labs/tree/master/frontend/pcap) and is available at [ahlyxlabs.com/pcap](https://ahlyxlabs.com/pcap). It connects to the agent at `ws://localhost:7777/ws`.

The dashboard shows flow observations, DNS query/answer metadata, counters, protocol distribution, and alerts. Alert IDs are stable and duplicate updates modify one rendered row instead of incrementing the unique alert count.

### Relay mode

`--relay` asks for explicit confirmation before requesting a relay session from `https://api.ahlyxlabs.com`. It sends flow metadata to the relay rather than using the local WebSocket, and prints a session-specific dashboard URL. Only use it when you intentionally want this remote relay behavior:

```powershell
.\pcap-agent start --relay --interface "<Npcap interface name>"
```

```bash
./pcap-agent start --relay --interface eth0
```

## Detection notes

| Observation | Current meaning |
| --- | --- |
| Periodic connection | A local-origin, unique TCP connection attempt repeats to the same destination service at low jitter over a minimum observation period. It is a `notice`, not proof of C2. |
| Possible port scan | One source makes unique initial TCP attempts to at least 15 destination ports on one destination within 10 seconds. It is a `warning`, not a confirmed scan. Horizontal scans are not covered. |
| Possible SYN flood / SYN pressure | Unique half-open initial SYNs directed at a selected-interface local service (destination IP + port) reach the configured threshold. SYN retransmissions do not add to that count; ordinary outbound connection bursts do not trigger this observation. |
| TCP retransmission | A repeated TCP data/sequence range; ACK-only packets are ignored. Retransmission is normal on imperfect networks and is informational. |
| TCP reset | A reset observed for a tracked session. It is informational; the agent does not infer RST injection. |
| MAC observation | Vendor lookup plus the locally administered-address bit. Locally administered does not mean spoofed. A MAC with multiple IPv4 addresses is informational only. |
| DNS visibility | Parsed DNS question and available answer metadata. No DNS-tunneling conclusion is made. |

No `critical` alert is generated by a single routine heuristic. Severity is intentionally conservative: `info`, `notice`, and `warning` are not evidence of confirmed compromise.

## Troubleshooting

**No interfaces found** — Verify Npcap is installed on Windows, or libpcap is installed on Linux/macOS. Run the terminal with the capture permissions described above. VPN/VM adapters are often visible even when the physical adapter is not; reinstall/update Npcap if Windows returns no adapters.

**Wrong interface selected** — Run `list-interfaces` and pass the exact name to `start --interface ...`. Auto-selection is intentionally simple and can choose a virtual adapter.

**Permission or capture-open error** — On Windows, reopen PowerShell/Terminal as Administrator. On Linux, run the capture command with `sudo` or arrange your distribution’s libpcap capabilities. On macOS, try the capture command with `sudo` and check macOS privacy/security policy.

**Npcap missing on Windows** — Install Npcap, then close and reopen the elevated terminal. `.\pcap-agent list-interfaces` should show Npcap adapters. A Go build may succeed without Npcap, but live capture will not.

**Build failure mentioning libpcap or CGO** — Install the platform development headers and a C compiler, then ensure `CGO_ENABLED` is not disabled. Linux needs `libpcap-dev`/`libpcap-devel`; macOS may need Homebrew `libpcap`; Windows source builds need a CGO-compatible toolchain and Npcap SDK/libpcap headers. Prebuilt release binaries avoid the source-build toolchain requirement but still need a capture driver/runtime.

**Dashboard cannot connect** — Start the agent first and confirm `http://localhost:7777/` returns JSON. The production Ahlyx Labs PCAP page connects to `ws://localhost:7777/ws`; browser and agent must be on the same machine in local mode. For a custom `--port`, use a client or dashboard configured for that matching local WebSocket endpoint.

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

CI installs libpcap on Linux and builds/tests the project. Release CI packages the four platform archives described above when a `v*` tag is pushed.

## Layout

```text
cmd/agent/  Cobra CLI and analysis pipeline
capture/    libpcap/Npcap interface discovery, BPF filtering, capture loop
analyze/    flow, TCP-session, cadence, scan, DNS, MAC, and statistics logic
ws/         local WebSocket hub/server and relay client
session/    local session identifier helper
```

The production frontend is maintained separately in `Ahlyx-Labs/frontend/pcap/`; it is not bundled with the agent.

## Limitations

- Capturing depends on local driver support and privilege; encrypted protocols are summarized from metadata, not decrypted.
- The default BPF filter excludes non-TCP/UDP/ICMP traffic before analysis.
- Auto interface selection is not default-route aware.
- Flow messages are generated per observed packet; aggregate flow state is used for counts/statistics. Under browser backpressure, flow/DNS updates may be dropped to preserve alert, status, and control delivery.
- The production dashboard is maintained separately from this agent repository.
- Detection is local, heuristic, and intentionally conservative. Review packet context and endpoint ownership before acting.

## License

[MIT](LICENSE)
