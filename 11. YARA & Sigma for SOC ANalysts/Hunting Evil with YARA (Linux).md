## Overview

When direct access to a system is restricted, memory captures can still allow us to investigate potential threats. By using YARA on these memory snapshots, Security Analysts can scan for indicators of compromise even when the system itself remains inaccessible.

### Key Process:
1. **Create YARA Rules**: Develop rules targeting memory-based malware traits or suspicious behaviors.
2. **Compile Rules**: Using `yarac`, compile YARA rules to `.yrc` binary format (optional for better performance).
3. **Capture Memory Image**: Use tools like DumpIt, MemDump, Belkasoft RAM Capturer, Magnet RAM Capture, FTK Imager, or LiME (Linux Memory Extractor).
4. **Scan Memory Image with YARA**: Run YARA on the memory image to detect matches.

## Example Memory Scan with YARA

- **Memory Image**: `compromised_system.raw` from `/home/htb-student/MemoryDumps`.
- **YARA Rule File**: `wannacry_artifacts_memory.yar` located in `/home/htb-student/Rules/yara`.

```bash
yara /home/htb-student/Rules/yara/wannacry_artifacts_memory.yar /home/htb-student/MemoryDumps/compromised_system.raw --print-strings
```

### Sample Output:
Detected patterns related to WannaCry ransomware, such as `tasksche.exe` and other known artifacts.

## Integrating YARA with Volatility for Memory Forensics

### Volatility Framework
Volatility is a robust tool for analyzing memory images across multiple OS platforms. Using YARA within Volatility (via the `yarascan` plugin), Analysts can scan for specific malware indicators within the memory.

### Example - Single Pattern Search

Searching for a specific hard-coded URI without a YARA file:

```bash
vol.py -f /home/htb-student/MemoryDumps/compromised_system.raw yarascan -U "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"
```

- **Output**: Finds occurrences of this URI within the memory image.

### Example - Multiple Rule Scanning

Applying a set of YARA rules using the `-y` option with Volatility:

```bash
vol.py -f /home/htb-student/MemoryDumps/compromised_system.raw yarascan -y /home/htb-student/Rules/yara/wannacry_artifacts_memory.yar
```

#### Sample YARA Rule for WannaCry

```yara
rule Ransomware_WannaCry {
    meta:
        author = "Madhukar Raina"
        version = "1.1"
        description = "Detect strings from WannaCry ransomware"
        reference = "https://www.virustotal.com"

    strings:
        $wannacry_payload_str1 = "tasksche.exe" fullword ascii
        $wannacry_payload_str2 = "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii
        $wannacry_payload_str3 = "mssecsvc.exe" fullword ascii
        $wannacry_payload_str4 = "diskpart.exe" fullword ascii
        $wannacry_payload_str5 = "lhdfrgui.exe" fullword ascii

    condition: 3 of them
}
```

- **Output**: Identifies specific WannaCry artifacts in the memory image.