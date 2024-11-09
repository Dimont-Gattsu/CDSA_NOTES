## Plugins in Wireshark

Wireshark includes several plugins accessible through the **Statistics** and **Analyze** tabs, which provide:
- Detailed reports on network traffic, such as top talkers and specific protocol conversations.
- Tools for tracking TCP streams, filtering conversation types, creating packet filters, and accessing expert insights on network traffic.

## Using the Statistics and Analyze Tabs

### Statistics Tab
The **Statistics** tab offers plugins for viewing reports about:
- Protocol breakdowns
- Top IP addresses and talkers
- Conversation types and more

### Analyze Tab
The **Analyze** tab allows users to:
- Follow and track TCP streams
- Filter by conversation types
- Prepare new packet filters
- Examine expert network diagnostics

## Following TCP Streams

Wireshark can reconstruct TCP packet streams into readable formats, enabling data extraction (e.g., images, files).

To follow a TCP stream:
1. **Right-click** on a packet from the desired stream.
2. Select **Follow > TCP Stream**.
3. A new window opens with the entire conversation in sequence.

Alternatively, apply a filter to view a specific TCP stream:
```plaintext
tcp.stream eq #
```
Using this filter helps isolate a conversation by displaying only the relevant packets.

## Extracting Data and Files from Captures

Wireshark can extract files from captured data streams if the entire conversation is captured. This is helpful when analyzing protocols like **FTP** (File Transfer Protocol) that transfers files between hosts.

To extract files:
1. Stop the capture.
2. Go to **File > Export** and select the desired protocol format (e.g., DICOM, HTTP, SMB).
   
For FTP, port 20 (data transfer) and port 21 (control commands) are used. Below are some filters to analyze FTP traffic:

### Key FTP Filters in Wireshark

| Filter                    | Purpose                                                                                                                                         |
|---------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------|
| `ftp`                     | Displays all FTP traffic, helpful to identify FTP activity between hosts.                                                                      |
| `ftp.request.command`     | Shows FTP commands over port 21, useful for identifying commands like login, listing, download, or upload. Often reveals usernames and file names. |
| `ftp-data`                | Displays data transferred over port 20, enabling file reconstruction by capturing data packets during file transfers.                           |

#### Steps to Reconstruct FTP Data from a .pcap

1. **Identify FTP Traffic**: Use the `ftp` display filter.
2. **Inspect FTP Commands**: Use `ftp.request.command` to see control commands, identify filenames, and check for login details.
3. **Extract Data**:
   - Use `ftp-data` to locate packets for specific file transfers.
   - Follow the TCP stream for the desired file transfer.
   - In the stream view, set **Show and save data as** to **Raw**.
   - Save the extracted content with the original filename.
4. **Verify the File Type**: Check the saved file to ensure proper extraction.

These methods provide a structured way to extract meaningful data from a network capture, offering deep insights into network activities, such as file transfers or protocol-specific interactions.