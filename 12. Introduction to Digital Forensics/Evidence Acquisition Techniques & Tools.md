Evidence acquisition is crucial in digital forensics, involving the meticulous collection of data from various sources to ensure its authenticity and legal admissibility.

## 1. Forensic Imaging

Forensic imaging involves creating an exact, bit-by-bit copy of storage media, essential for preserving the original state of data. Tools for forensic imaging include:

- **FTK Imager**: Allows creation of perfect disk copies, viewing and analyzing data without alteration.
- **AFF4 Imager**: Open-source tool supporting multiple file systems with compressed imaging capabilities.
- **DD and DCFLDD**: Unix-based command-line utilities; DCFLDD includes forensic-specific enhancements like hashing.
- **Virtualization Tools**: Used to acquire images from virtual environments, often through snapshots.

### Example: Imaging with FTK Imager
1. Select **File > Create Disk Image**.
2. Choose the source (Physical/Logical Drive) and specify the destination.
3. Set image type, fragmentation, and compression, then **Start**.
4. After imaging, FTK Imager verifies and summarizes the results.

### Example: Mounting Disk Image with Arsenal Image Mounter
1. Run **Arsenal Image Mounter** as admin.
2. Mount the image as **read-only** to maintain integrity.
3. The image appears as a drive, e.g., `D:\`.

## 2. Extracting Host-based Evidence & Rapid Triage

Host-based evidence includes artifacts from operating systems like Windows, generated by application execution, file modifications, and user activity. Evidence acquisition is categorized by data volatility:

- **Volatile Data**: Captured from active memory and includes live memory contents, often containing traces of malware.
  - **Memory Acquisition Tools**:
    - **WinPmem**: Open-source memory capture tool for Windows.
    - **DumpIt**: Simple tool for Windows/Linux memory dumps.
    - **MemDump**: CLI tool capturing system RAM.
    - **Magnet RAM Capture**: Free memory capture tool from Magnet Forensics.
- **Non-volatile Data**: Persists on disk and includes registry entries, Windows Event Logs, and system or application artifacts.

### Example: Memory Acquisition with WinPmem
```bash
C:\Users\X\Downloads> winpmem_mini_x64_rc2.exe memdump.raw
```

### Rapid Triage with KAPE
KAPE (Kroll Artifact Parser and Extractor) accelerates evidence collection by gathering essential artifacts.

1. **Targets**: Define the data to collect, stored as `.tkape` files in the `KAPE\Targets` directory.
2. **Execution**:
   - Set source (`D:\`) and destination paths.
   - Use **gkape.exe** (GUI) to configure options and start the collection.
3. Results include $MFT and other system directories in the output directory.

### Remote Collection with EDR & Velociraptor
- **EDR Solutions**: Facilitate remote evidence gathering, with capabilities for searching across networks.
- **Velociraptor**: Uses VQL queries and Hunts to gather artifacts like **Windows.KapeFiles.Targets**.

## 3. Extracting Network Evidence

Network evidence analysis is foundational for SOC analysts, involving tools and data sources that capture and interpret network traffic.

- **Traffic Capture**: Tools like **Wireshark** and **tcpdump** capture packets to analyze network communication.
- **IDS/IPS Systems**: IDS (Intrusion Detection Systems) detect, while IPS (Intrusion Prevention Systems) detect and block suspicious activity.
- **Traffic Flow Data**: Tools like **NetFlow** provide high-level traffic behavior insights.
- **Firewall Logs**: Offer information on attempted exploits and unauthorized access attempts.
