A Snort rule is a powerful tool to identify and flag potential malicious activity in network traffic.

While Snort rules resemble Suricata rules with a structure comprising a rule header and rule options, the Snort documentation provides comprehensive guidance for crafting effective rules. See [Snort Documentation](https://docs.snort.org/) and [Suricata Rules Differences](https://docs.suricata.io/en/latest/rules/differences-from-snort.html) for further reference.

To explore these rules in practice, SSH into the provided target system to replicate and understand the commands demonstrated in this section.

---

## Example 1: Detecting Ursnif (Inefficiently)

```plaintext
alert tcp any any -> any any (msg:"Possible Ursnif C2 Activity"; flow:established,to_server; content:"/images/", depth 12; content:"_2F"; content:"_2B"; content:"User-Agent|3a 20|Mozilla/4.0 (compatible|3b| MSIE 8.0|3b| Windows NT"; content:!"Accept"; content:!"Cookie|3a|"; content:!"Referer|3a|"; sid:1000002; rev:1;)
```

This rule detects Ursnif malware by matching specific patterns in HTTP traffic:

- `flow:established,to_server;` matches established TCP connections to the server.
- `content:"/images/", depth 12;` looks for `/images/` within the first 12 bytes.
- Additional `content` fields match other patterns, like `"_2F"`, `"_2B"`, and specific HTTP headers.
- `!` in `content:!"Accept";` indicates the absence of certain headers.

Test the rule on `ursnif.pcap`:
```bash
sudo snort -c /root/snorty/etc/snort/snort.lua --daq-dir /usr/local/lib/daq -R /home/htb-student/local.rules -r /home/htb-student/pcaps/ursnif.pcap -A cmg
```

---

## Example 2: Detecting Cerber

```plaintext
alert udp $HOME_NET any -> $EXTERNAL_NET any (msg:"Possible Cerber Check-in"; dsize:9; content:"hi", depth 2, fast_pattern; pcre:"/^[af0-9]{7}$/R"; detection_filter:track by_src, count 1, seconds 60; sid:2816763; rev:4;)
```

This rule targets Cerber malware:

- `dsize:9;` restricts the rule to datagrams with a 9-byte payload.
- `content:"hi", depth 2, fast_pattern;` searches the first two bytes for `hi`.
- `pcre` checks for seven hex characters following `hi`.
- `detection_filter` limits alert frequency by source.

Run the rule on `cerber.pcap`:
```bash
sudo snort -c /root/snorty/etc/snort/snort.lua --daq-dir /usr/local/lib/daq -R /home/htb-student/local.rules -r /home/htb-student/pcaps/cerber.pcap -A cmg
```

---

## Example 3: Detecting Patchwork

```plaintext
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"OISF TROJAN Targeted AutoIt FileStealer/Downloader CnC Beacon"; flow:established,to_server; http_method; content:"POST"; http_uri; content:".php?profile="; http_client_body; content:"ddager=", depth 7; http_client_body; content:"&r1=", distance 0; http_header; content:!"Accept"; http_header; content:!"Referer|3a|"; sid:10000006; rev:1;)
```

This rule detects Patchwork APT malware by matching HTTP patterns:

- `flow:established,to_server;` specifies outbound connections.
- `http_method; content:"POST";` requires HTTP `POST` requests.
- `http_client_body` and `http_header` filter for specific content and missing headers.

Test with `patchwork.pcap`:
```bash
sudo snort -c /root/snorty/etc/snort/snort.lua --daq-dir /usr/local/lib/daq -R /home/htb-student/local.rules -r /home/htb-student/pcaps/patchwork.pcap -A cmg
```

---

## Example 4: Detecting Patchwork (SSL)

```plaintext
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"Patchwork SSL Cert Detected"; flow:established,from_server; content:"|55 04 03|"; content:"|08|toigetgf", distance 1, within 9; classtype:trojan-activity; sid:10000008; rev:1;)
```

This SSL rule detects Patchwork malware through certificate patterns:

- `content:"|55 04 03|";` targets ASN.1 common name fields in X.509 certificates.
- `distance` and `within` further refine the search.

Run with `patchwork.pcap`:
```bash
sudo snort -c /root/snorty/etc/snort/snort.lua --daq-dir /usr/local/lib/daq -R /home/htb-student/local.rules -r /home/htb-student/pcaps/patchwork.pcap -A cmg
```