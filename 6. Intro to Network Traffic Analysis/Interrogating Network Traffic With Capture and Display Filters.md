## Lab Objectives
- Practice filtering captured network traffic to extract meaningful data.
- Identify servers answering DNS and HTTP/S requests.
- Analyze traffic patterns and connections.

| **Task**                             | **Description**                                                                                           | **Command/Details**                                                                                               |
|--------------------------------------|-----------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------|
| **Task 1: Read a Capture File Without Filters** | Begin by examining the `.pcap` file without applying any filters.                                        | `tcpdump -r (file.pcap)`                                                                                          |
| **Task 2: Identify Traffic Types**   | Examine the traffic to identify protocols and ports.                                                      | - **Common Protocols**: DNS, HTTP, HTTPS <br> - **Ports Utilized**: 53 (DNS), 80 (HTTP), 443 (HTTPS)              |
| **Task 3: Identify Conversations and Patterns** | Analyze for patterns between servers and hosts.                                                          | - **Patterns**: Connections between server and host <br> - **Three-Way Handshake**: Note client/server ports <br> - **Servers**: Communicate over well-known ports <br> - **Receiving Hosts**: Use high random ports <br> - Command with Absolute Sequence Numbers: `tcpdump -S -r (file.pcap)` |
| **Task 4: In-Depth Capture Analysis** | Answer questions on timestamps, DNS responses, and protocols.                                             | - **First Conversation Timestamp**: Look for first TCP handshake (SYN/SYN-ACK/ACK) <br> - **DNS Server Response**: IP for `apache.org` <br> - **Protocol**: Identify via port numbers <br> - **Example Commands**: `tcpdump -r (file.pcap) -nn` <br> `tcpdump -r (file.pcap) src host [host-name]` |
| **Task 5: Filter Out Non-DNS Traffic** | Filter to isolate DNS traffic for analysis on domain names and DNS records.                               | - **Filter for DNS Traffic**: `sudo tcpdump -r (file.pcap) udp and port 53` <br> - **Hex and ASCII Output**: `tcpdump -X -r (file.pcap)` |
| **Task 6: Filter for TCP (HTTP/HTTPS) Traffic** | Isolate HTTP/HTTPS traffic to identify web servers and analyze HTTP requests.                            | - **Filter Command**: `tcpdump -r (file.pcap) 'port 80 or port 443'` <br> - **Analyze Requests**: Identify common HTTP methods (e.g., GET, POST) and response codes |
| **Task 7: Analyze First Conversation Server** | Examine the server in the first conversation for application or server type details.                      | - **Command with Hex and ASCII Output**: `tcpdump -X -r (file.pcap)` <br> - **Check Server Response**: Look for clues in the HTTP response data for application/server information |
## Analysis Tips

Consider these questions to guide your analysis:
- What types of traffic are present (protocols, ports)?
- How many unique conversations and hosts?
- What is the timestamp of the first TCP conversation?
- How can traffic be filtered to simplify analysis?
- Which servers are responding on well-known ports?
- What types of DNS records and HTTP methods are used?

