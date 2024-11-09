## Introduction to Tcpdump
**Tcpdump** is a command-line packet sniffer that captures and interprets data frames from network interfaces. Available on Unix-based systems, Tcpdump can capture packets from the network "off the wire" and is widely used for traffic analysis, troubleshooting, and forensic purposes. It requires root privileges to access hardware and run effectively, typically via `sudo`. Windows users can use **WinDump** or run a Linux distribution in WSL to leverage Tcpdump on Windows.

## Basic Capture Options
Tcpdump provides many switches to modify captures. Here are key options:

| Switch              | Description                                           |
| ------------------- | ----------------------------------------------------- |
| `-D`                | Display available interfaces.                         |
| `-i`                | Select an interface to capture from, e.g., `-i eth0`. |
| `-n`                | Do not resolve hostnames.                             |
| `-nn`               | Do not resolve hostnames or port names.               |
| `-e`                | Include Ethernet header in the output.                |
| `-X`                | Show packet contents in hex and ASCII.                |
| `-v`, `-vv`, `-vvv` | Increase verbosity level.                             |
| `-c`                | Capture a specific number of packets then exit.       |
| `-s`                | Specify the packet capture length.                    |
| `-S`                | Show absolute sequence numbers.                       |
| `-q`                | Print minimal protocol info.                          |
| `-r`                | Read from a file.                                     |
| `-w`                | Write to a file.                                      |
|                     |                                                       |
### Display Available Interfaces
```bash
sudo tcpdump -D
```

### Capture Traffic on a Specific Interface
```bash
sudo tcpdump -i eth0
```

### Disable Host and Port Resolution
```bash
sudo tcpdump -i eth0 -nn
```

### Include Ethernet Header in Capture
```bash
sudo tcpdump -i eth0 -e
```

### Show Hex and ASCII Output
```bash
sudo tcpdump -i eth0 -X
```

### Combine Multiple Options
```bash
sudo tcpdump -i eth0 -nnvXX
```

## Tcpdump Output Breakdown
Tcpdump output can include various fields:

| Field | Description |
| ----- | ----------- |
| **Timestamp** | Shows time of capture. |
| **Protocol** | Upper-layer protocol (e.g., IP). |
| **Source & Destination IP/Port** | Shows the connection path and ports. |
| **Flags** | Displays any TCP flags used. |
| **Sequence & Ack Numbers** | Used to track TCP segments. |
| **Protocol Options** | TCP options like window size, SACK, etc. |

## File Input/Output with Tcpdump

### Save Captures to a File
```bash
sudo tcpdump -i eth0 -w ~/output.pcap
```

### Read Captures from a File
```bash
sudo tcpdump -r ~/output.pcap
```

To increase detail when reading from a file, add relevant switches.

## Advanced Tcpdump Use
Tcpdump can act as a basic IDS by using filters in a script to detect specific patterns, such as repeated ICMP requests from a single IP, and can then trigger automated responses.