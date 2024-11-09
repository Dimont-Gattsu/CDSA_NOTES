Often, unusual HTTP/HTTPS traffic patterns indicate potential attacks on web servers. Attackers may exploit transport layer vulnerabilities to gather information, explore, or exploit web applications.

---

## Detecting Fuzzing Attempts

Fuzzing attempts can be identified through:
- **Excessive HTTP/HTTPS traffic** from a single host.
- Checking web server **access logs** for repetitive or unusual access attempts.

Attackers often initiate fuzzing to discover server details before an attack. Web Application Firewalls (WAFs) may block such activity, though internal servers may be more vulnerable.

---

## Finding Directory Fuzzing

Directory fuzzing allows attackers to probe for web pages and directories. This can be detected in traffic analysis by filtering for `http` traffic in Wireshark.

1. **Basic Filter**:
   ```plaintext
   http
   ```

2. **Isolating Requests**: To exclude server responses, specify `http.request`.

### Indicators of Directory Fuzzing

- **Repeated 404 Responses**: Frequent attempts to access non-existent files.
- **Rapid Request Sequences**: Multiple requests sent quickly.

### Checking Access Logs

On an Apache server, use the following commands to filter logs by IP address.

- **Using `grep`**:
   ```bash
   cat access.log | grep "192.168.10.5"
   ```
   
- **Using `awk`**:
   ```bash
   cat access.log | awk '$1 == "192.168.10.5"'
   ```

Example log entries:
```
192.168.10.5 - - [18/Jul/2023:12:58:07 -0600] "GET /randomfile1 HTTP/1.1" 404 435 "-" "Mozilla/4.0"
192.168.10.5 - - [18/Jul/2023:12:58:07 -0600] "GET /.bash_history HTTP/1.1" 404 435 "-" "Mozilla/4.0"
...
```

---

## Detecting Other Fuzzing Techniques

Attackers may target dynamic or static webpage elements, like `id` fields, or test for IDOR vulnerabilities, especially with JSON parsing.

- **Filtering Specific Hosts**:
   ```plaintext
   http.request and ((ip.src_host == <suspected IP>) or (ip.dst_host == <suspected IP>))
   ```

To examine the entire request sequence:
- Right-click any request and select **Follow > HTTP Stream** in Wireshark.

**Indicators of Fuzzing Attempts**:
- Rapid request patterns suggest fuzzing.
- Advanced attackers may stagger requests over time or distribute them across multiple IPs to evade detection.

---

## Preventing Fuzzing Attempts

To counteract fuzzing:
- **Adjust Server Configurations**: Configure `virtualhost` or access settings to return correct response codes.
- **Use WAF Rules**: Block specific IPs or patterns of suspicious behavior to protect the server.
