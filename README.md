# Network Traffic Analyzer — Anomaly Detection

A Python-based network traffic analysis tool that reads `.pcap` and `.pcapng` files, extracts packet metadata, and detects suspicious behavior based on connection volume thresholds.

Built as a practical cybersecurity project focused on Blue Team skills — specifically network reconnaissance detection and SOC analyst workflows.

---

## Features

- Parses `.pcap` and `.pcapng` capture files
- Extracts source/destination IPs, ports, and transport protocol per packet
- Detects anomalies based on configurable packet volume threshold
- Filters ephemeral ports to reduce false positives from legitimate return traffic
- Whitelist support for common legitimate ports (HTTP, HTTPS, DNS, SSH, etc.)
- Command-line interface for flexible file input

---

## Detection Logic

The tool flags an IP as suspicious when:

1. It sends more than `THRESHOLD` packets to a single destination port
2. The destination port is a **well-known port** (below 1024)
3. The destination port is **not whitelisted** as common legitimate traffic

This approach targets behaviors such as:
- Port scanning and service enumeration (e.g., Nmap, DCERPC endpoint discovery)
- Repeated probing of sensitive ports (SMB/445, RDP/3389, Telnet/23)

---

## Project Structure

```
network-traffic-analyzer/
│
├── src/                  → Main Python script
├── samples/              → Sample .pcap files used for testing
├── docs/                 → Research notes, screenshots, and analysis
├── requirements.txt      → Python dependencies
└── README.md
```

---

## Requirements

- Python 3.x
- [Wireshark / TShark](https://www.wireshark.org/) installed and accessible in PATH
- Dependencies listed in `requirements.txt`

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Usage

```bash
python src/analyzer.py <path_to_file.pcapng>
```

**Example:**

```bash
python src/analyzer.py samples/discovery_scan_dcerpc.pcapng
```

**Example output:**

```
Processing archive: samples/discovery_scan_dcerpc.pcapng
[TCP] Source IP:10.0.2.17 and port:45949 ---> Destination IP:10.0.2.18 and port:135
[TCP] Source IP:10.0.2.18 and port:135 ---> Destination IP:10.0.2.17 and port:45949
...
[ALERT] IP 10.0.2.17 sent 350 packets to port 135
```

---

## Configuration

You can adjust detection sensitivity by editing the constants in `src/analyzer.py`:

| Constant | Default | Description |
|---|---|---|
| `THRESHOLD` | `10` | Minimum packet count to trigger an alert |
| `WHITELIST_PORTS` | `{20,21,22,23,25,53,80,110,143,443}` | Ports excluded from alerting |

> **Note:** Lowering the threshold increases sensitivity but may generate more false positives. Raising it reduces noise but may miss low-volume attacks (low and slow attacks).

---

## Test Results

| File | Packets | Detection | Result |
|---|---|---|---|
| `discovery_scan_dcerpc_endpoint_mapper.pcapng` | 700 (350 origin) | IP 10.0.2.17 → port 135 | ✅ Detected |
| `Discovery_dcerp_srvsvc_NetShareEnum.pcapng` | 36 | IP 172.16.66.1 → port 445 | ✅ Detected (threshold=10) |
| Self-generated legitimate traffic | ~200 | No suspicious behavior | ✅ Zero false positives |

---

## Limitations

- **Fixed threshold** — not adaptive. Real SOC environments use dynamic baseline analysis to distinguish normal from abnormal traffic patterns.
- **Low and slow attacks** — attackers that spread requests over a long time window may not trigger the threshold.
- **No payload inspection** — detection is based on packet metadata only (IPs, ports, volume), not packet content.
- **No real-time capture** — currently analyzes existing `.pcap` files only; live capture is not supported.

---

## Tools & Technologies

- **Python 3** — core language
- **PyShark** — packet parsing via TShark wrapper
- **Wireshark / TShark** — underlying capture engine
- **Collections.Counter** — efficient packet counting
- **Argparse** — command-line interface

---

## Sample Captures

Test files sourced from:
- [NETRESEC](https://www.netresec.com/?page=PcapFiles) — curated network capture repository
- Self-generated captures using Wireshark on a controlled local network

---

## Author

**Caique** — Cybersecurity student focused on Blue Team, SOC, and Defensive Security.

→ [LinkedIn](https://linkedin.com/in/caique-oliveira77/)  
