## TShark vs. Wireshark
TShark is a terminal-based tool with features similar to Wireshark and uses the same filters and syntax. TShark is ideal for command-line environments, while Wireshark offers a rich GUI experience.

### Basic TShark Commands
| Command | Description |
| ------- | ----------- |
| `-D`    | Display available interfaces for capture |
| `-L`    | List link-layer types available |
| `-i`    | Select interface for capture |
| `-f`    | Set packet filter in libpcap syntax |
| `-c`    | Capture a set number of packets, then quit |
| `-a`    | Set an autostop condition (by duration, file size, or packet count) |
| `-r`    | Read from a file |
| `-W`    | Write to file in pcapng format |
| `-P`    | Print packet summary while writing |
| `-x`    | Show hex and ASCII output |
| `-h`    | Display help menu |

To view all options:
```bash
tshark -h
```

### Example TShark Commands
- **Capture on an interface and save to file**:
  ```bash
  sudo tshark -i eth0 -w /tmp/test.pcap
  ```
- **Apply filter for specific host**:
  ```bash
  sudo tshark -i eth0 -f "host 172.16.146.2"
  ```

## Wireshark GUI Walkthrough
### Three Main Panes
1. **Packet List Pane**: Displays each packet’s summary, including order, time, source, destination, protocol, and information.
2. **Packet Details Pane**: Shows protocol details in the OSI Model format. Layers are shown in reverse order (lower to higher).
3. **Packet Bytes Pane**: Shows the packet in ASCII or hex, highlighting selected fields from the Packet Details pane.

#### Capture Filters
Capture filters, using BPF syntax, limit data written to disk. Some examples:

| Filter                  | Description                                |
| ----------------------- | ------------------------------------------ |
| `host x.x.x.x`          | Capture traffic for a specific host       |
| `net x.x.x.x/24`        | Capture traffic for a specific network    |
| `port #`                | Capture traffic for a specific port       |
| `not port #`            | Capture everything except a specific port |
| `portrange x-x`         | Capture traffic within a port range       |
| `broadcast` / `multicast` | Capture one-to-many or one-to-all traffic |

To view available capture filters:
1. **Capture menu** > **Capture Filters**.

#### Display Filters
Display filters can be applied to live or recorded captures and offer a wide range of protocol-based filtering options. Examples include:

| Filter                   | Description                                |
| ------------------------ | ------------------------------------------ |
| `ip.addr == x.x.x.x`     | Show traffic involving a specific host     |
| `ip.src/dst == x.x.x.x`  | Show traffic from/to a specific host       |
| `dns` / `tcp` / `arp`    | Filter by protocol                         |
| `tcp.port == x`          | Filter by a specific TCP port              |
| `tcp.port != x`          | Exclude traffic from a specific port       |
| `and` / `or` / `not`     | Combine conditions                         |

Applying a display filter:
- Enter a filter in the **Display Filter** field in the Wireshark capture window. A valid filter turns the field green.

### Practical Note
Filtering by protocol (like `HTTP`) may differ from filtering by port (e.g., `80`), as protocols often utilize additional identifiers like `GET` or `POST` for HTTP traffic.