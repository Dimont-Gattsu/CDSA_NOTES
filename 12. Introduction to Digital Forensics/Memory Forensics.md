## Types of Data in RAM Useful for Investigations

- **Network connections**
- **File handles & Open Files**
- **Registry keys**
- **Running processes**
- **Loaded DLLs & Drivers**
- **Console command history**
- **User credentials**
- **Malware artifacts**
- **System configurations**

### Process for Memory Forensics

1. **Process Identification and Verification**  
   - Enumerate running processes, validate origins, and check against known legitimate processes.

2. **Process Component Analysis**  
   - Examine associated DLLs and handles, looking for unauthorized injections.

3. **Network Activity Review**  
   - Analyze active connections, IPs, and domains to trace external communications.

4. **Code Injection Detection**  
   - Identify techniques like process hollowing by examining memory anomalies.

5. **Rootkit Detection**  
   - Identify deep-seated malware that embeds in OS using elevated privileges.

6. **Suspicious Elements Extraction**  
   - Isolate suspicious components for detailed forensic examination.

## The Volatility Framework

### Overview

Volatility is an open-source memory forensics tool used on various platforms to dissect memory images across operating systems, including Windows, macOS, and Linux.

#### Common Volatility Modules
- **pslist**: Lists running processes.
- **cmdline**: Shows command-line arguments.
- **netscan**: Identifies network connections.
- **malfind**: Detects malicious code in processes.
- **handles**: Lists open handles.
- **svcscan**: Scans Windows services.
- **dlllist**: Lists loaded DLLs.
- **hivelist**: Lists registry hives in memory.

### Volatility Usage Examples

- **Forensics with Volatility Help**:
  ```bash
  vol.py --help
  ```

- **List Running Processes**:
  ```bash
  vol.py -f /path/to/memory.dump --profile=Win7SP1x64 pslist
  ```

- **Network Artifact Scanning**:
  ```bash
  vol.py -f /path/to/memory.dump --profile=Win7SP1x64 netscan
  ```

- **Detect Injected Code**:
  ```bash
  vol.py -f /path/to/memory.dump --profile=Win7SP1x64 malfind --pid=608
  ```

- **List Loaded DLLs for Specific Process**:
  ```bash
  vol.py -f /path/to/memory.dump --profile=Win7SP1x64 dlllist -p 1512
  ```

- **List Windows Services**:
  ```bash
  vol.py -f /path/to/memory.dump --profile=Win7SP1x64 svcscan
  ```

## Rootkit Detection Using psscan and pslist Plugins

- **psscan** plugin reveals processes hidden by rootkits:
  ```bash
  vol.py -f /path/to/rootkit.dump psscan
  ```

## Memory Analysis Using Strings

- **IPv4 Address Search**:
  ```bash
  strings /path/to/memory.dump | grep -E "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b"
  ```

- **Email Address Extraction**:
  ```bash
  strings /path/to/memory.dump | grep -oE "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,4}\b"
  ```

- **Command Line Artifacts**:
  ```bash
  strings /path/to/memory.dump | grep -E "(cmd|powershell|bash)[^\s]+"
  ```