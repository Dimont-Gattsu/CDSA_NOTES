Snort is an open-source tool functioning as an Intrusion Detection System (IDS) and Intrusion Prevention System (IPS). It can also act as a packet logger or sniffer. Snort inspects all network traffic and can log every activity, providing visibility and comprehensive logging at the application layer. Specific rule sets direct Snort on what to inspect and identify.

---

## Snort Operation Modes

Snort operates in several modes:
1. **Inline IDS/IPS**: Enables active traffic blocking in IPS mode.
2. **Passive IDS**: Observes and logs traffic without blocking.
3. **Network-based IDS**: Monitors network traffic from multiple hosts.
4. **Host-based IDS**: Rarely used for Snort; specialized tools are preferable.

**DAQ (Data Acquisition)**:
- Snort uses DAQ modules to interface with network data sources.
- Modes:
  - **Passive**: Observes traffic but doesn’t block it.
  - **Inline**: Blocks traffic in specific scenarios (e.g., `-Q` flag with `afpacket` DAQ).

---

## Snort Architecture

1. **Packet Sniffer**: Decodes network traffic, forwarding packets to Preprocessors.
2. **Preprocessors**: Analyze packet types and behaviors. Configured in `snort.lua`, these modules perform tasks such as detecting HTTP traffic or scanning.
3. **Detection Engine**: Matches packets against Snort rules.
4. **Logging and Alerting**: Logs matched packets, typically in syslog or databases, managed by Output plugins in `snort.lua`.

---

## Snort Configuration

**Configuration Files**:
- `snort.lua`: Main configuration file for Snort, with sections for network variables, decoders, detection engines, and output configurations.
- **Default Configurations**: Provided by `snort_defaults.lua`, this file initializes default configurations.

To view or edit the configuration file:
```bash
sudo more /root/snorty/etc/snort/snort.lua
```

### Validating Snort Configuration
To validate configuration:
```bash
sudo snort -c /root/snorty/etc/snort/snort.lua --daq-dir /usr/local/lib/daq
```

---

## Snort Inputs

### Running Snort on PCAP Files
To observe Snort’s behavior with a PCAP file:
```bash
sudo snort -c /root/snorty/etc/snort/snort.lua --daq-dir /usr/local/lib/daq -r /path/to/pcapfile.pcap
```

### Running Snort on an Active Network Interface
To actively monitor network traffic:
```bash
sudo snort -c /root/snorty/etc/snort/snort.lua --daq-dir /usr/local/lib/daq -i interface_name
```

---

## Snort Rules

Snort rules consist of headers and options. They can be configured within `snort.lua` under the `ips` section:
```lua
ips = {
    { variables = default_variables, include = '/path/to/rules/file.rules' }
}
```

### Loading Rules via Command Line
1. **Single File**: `-R /path/to/rules/file.rules`
2. **Directory of Rules**: `--rule-path /path/to/rules`

---

## Snort Outputs

Snort provides various output types for alerting and statistics:

1. **Basic Statistics**: Summarizes packet counts, activity counts, file statistics, and runtime performance.
2. **Alert Outputs**:
   - `-A cmg`: Combines fast alerting with packet headers and payload.
   - `-A u2`: Unified2 binary format, used for post-processing.
   - `-A csv`: CSV format output.

3. **Performance Statistics**: Tracks runtime performance, providing memory and CPU utilization details, helpful for optimizing system performance.

To list available output plugins:
```bash
snort --list-plugins | grep logger
```

Example of `-A cmg` alert output:
```bash
sudo snort -c /root/snorty/etc/snort/snort.lua --daq-dir /usr/local/lib/daq -r /path/to/pcapfile.pcap -A cmg
```

---

## Snort Key Features

1. Deep packet inspection and logging.
2. Real-time intrusion detection.
3. Network security monitoring.
4. Support for IPv4 and IPv6 traffic.
5. Anomaly detection and multi-tenant support.