## Intrusion Detection Examples

### Example 1: Detecting Beaconing Malware

**Beaconing** is a repetitive process used by malware to communicate with command and control (C2) servers. This behavior can often be detected by analyzing connection patterns in `conn.log`, identifying repetitive connections to the same IP, constant data size, or timing patterns. The following command uses Zeek to analyze a beaconing malware sample:

```bash
/usr/local/zeek/bin/zeek -C -r /home/htb-student/pcaps/psempire.pcap
cat conn.log
```

Inspecting `conn.log` reveals beaconing behavior (connections to `51.15.197.127:80` every 5 seconds) typical of PowerShell Empire.

### Example 2: Detecting DNS Exfiltration

DNS exfiltration, which mimics normal traffic, can be identified by analyzing Zeek's `files.log` or `dns.log` for large data transfers or covert channels. `dns.log` may show unusual domains or subdomain patterns, as seen here:

```bash
/usr/local/zeek/bin/zeek -C -r /home/htb-student/pcaps/dnsexfil.pcapng
cat dns.log | /usr/local/zeek/bin/zeek-cut query | cut -d . -f1-7
```

Frequent subdomains like `456c54f2.blue.letsgohunt.online` indicate potential DNS tunneling.

### Example 3: Detecting TLS Exfiltration

TLS exfiltration may be detected by looking at high data transfer volumes between specific hosts. The `conn.log` file can be filtered and aggregated to identify unusual data sizes:

```bash
/usr/local/zeek/bin/zeek -C -r /home/htb-student/pcaps/tlsexfil.pcap
cat conn.log | /usr/local/zeek/bin/zeek-cut id.orig_h id.resp_h orig_bytes | \
sort | grep -v -e '^$' | grep -v '-' | datamash -g 1,2 sum 3 | sort -k 3 -rn | head -10
```

This shows ~270 MB of data sent to `192.168.151.181`.

### Example 4: Detecting PsExec Activity

**PsExec** is commonly used in remote administration and attacks. When transferred over SMB and executed via IPC, `smb_files.log`, `dce_rpc.log`, and `smb_mapping.log` can help identify this activity.

```bash
/usr/local/zeek/bin/zeek -C -r /home/htb-student/pcaps/psexec_add_user.pcap
cat smb_files.log
cat dce_rpc.log
cat smb_mapping.log
```

The logs display the transfer of `PSEXESVC.exe` and its execution, highlighting PsExec’s typical activity.

## Commands and Tools Summary

- **Zeek-cut**: Extracts specified columns from Zeek logs.
- **Sort**: Orders log data for easier analysis.
- **Grep**: Filters log data.
- **Datamash**: Aggregates data, useful for summing and grouping fields.
  
Each command aids in refining and focusing the output, making suspicious patterns more apparent. Analyzing logs using tools like Wireshark or Zeek-cut allows detailed inspection of traffic.