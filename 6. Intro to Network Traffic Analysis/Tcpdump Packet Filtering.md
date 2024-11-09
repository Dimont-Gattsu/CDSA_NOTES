Using advanced filtering options allows us to reduce the amount of traffic printed to output or written to disk, thereby saving space and speeding up data processing. Filters can be paired with standard tcpdump syntax to capture broadly or narrow down to specific hosts or TCP flags. Advanced filters enable tailored captures.

### Helpful Tcpdump Filters

| Filter      | Result                                                                                               |
|-------------|------------------------------------------------------------------------------------------------------|
| `host`      | Filters visible traffic to show anything involving the designated host (bi-directional).             |
| `src`/`dest`| Designate source or destination host or port.                                                        |
| `net`       | Filters traffic from or to the specified network using / notation.                                   |
| `proto`     | Filters for a specific protocol (e.g., ether, TCP, UDP, ICMP).                                       |
| `port`      | Filters any traffic with the specified port as source or destination.                                |
| `portrange` | Allows filtering by port range (e.g., 0-1024).                                                       |
| `less`/`greater` | Filters packets based on size.                                                                   |
| `and`/`&&`  | Combines filters, showing packets that meet both conditions.                                         |
| `or`        | Matches any of two conditions.                                                                       |
| `not`       | Negates a condition, e.g., `not UDP` shows non-UDP traffic.                                          |

### Examples of Common Filters

- **Host Filter**
  ```bash
  sudo tcpdump -i eth0 host 172.16.146.2
  ```

- **Source/Destination Filter**
  ```bash
  sudo tcpdump -i eth0 src host 172.16.146.2
  ```

- **Source Port Filter**
  ```bash
  sudo tcpdump -i eth0 tcp src port 80
  ```

- **Destination Net Filter**
  ```bash
  sudo tcpdump -i eth0 dest net 172.16.146.0/24
  ```

- **Protocol Filter by Name**
  ```bash
  sudo tcpdump -i eth0 udp
  ```

- **Protocol Filter by Number**
  ```bash
  sudo tcpdump -i eth0 proto 17
  ```

- **Port Filter**
  ```bash
  sudo tcpdump -i eth0 tcp port 443
  ```

- **Port Range Filter**
  ```bash
  sudo tcpdump -i eth0 portrange 0-1024
  ```

- **Less/Greater Filter**
  ```bash
  sudo tcpdump -i eth0 less 64
  ```

- **Greater Filter for Packets Over 500 Bytes**
  ```bash
  sudo tcpdump -i eth0 greater 500
  ```

### Combining Filters with `AND` and `OR`

- **AND Filter Example**
  ```bash
  sudo tcpdump -i eth0 host 192.168.0.1 and port 23
  ```

- **OR Filter Example**
  ```bash
  sudo tcpdump -r sus.pcap icmp or host 172.16.146.1
  ```

- **NOT Filter Example**
  ```bash
  sudo tcpdump -r sus.pcap not icmp
  ```

## Pre-Capture vs. Post-Capture Processing

Applying filters during capture omits unmatched traffic, reducing data volume but risking the loss of potentially valuable information. Filtering during post-capture analysis parses the capture file, displaying only packets that meet the filter criteria without altering the original file.

## Interpreting Tips and Tricks

- **Absolute Sequence Numbers**: Use `-S` to display them for detailed tracking.
- **Verbose Output**: Use `-v`, `-X`, and `-e` for capturing more data.
- **Selective Display**: Options like `-c`, `-n`, `-s`, `-S`, and `-q` help modify displayed data.
- **ASCII Display**: Use `-A` to show only ASCII text, useful for human-readable output.

### ASCII Mode with `-A`

```bash
sudo tcpdump -Ar telnet.pcap
```

### Piping Output to Grep

```bash
sudo tcpdump -Ar http.cap -l | grep 'mailto:*'
```

This method filters output to quickly search for specific terms or patterns within the capture.

## Advanced Packet Filtering Using TCP Flags

```bash
tcpdump -i eth0 'tcp[13] &2 != 0'
```

This command checks if the SYN flag in the TCP header is set.

## Protocol RFC Links

| Protocol       | RFC                                                                                             |
|----------------|-------------------------------------------------------------------------------------------------|
| IP Protocol    | [RFC 791](https://datatracker.ietf.org/doc/html/rfc791)                                         |
| ICMP Protocol  | [RFC 792](https://datatracker.ietf.org/doc/html/rfc792)                                         |
| TCP Protocol   | [RFC 793](https://datatracker.ietf.org/doc/html/rfc793)                                         |
| UDP Protocol   | [RFC 768](https://datatracker.ietf.org/doc/html/rfc768)                                         |
| RFC Quick Links| [Wikipedia RFC Links](https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers)                |
