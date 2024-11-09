## Scenario Setup

- **Target System Access**: Use RDP to connect to the Target IP with provided credentials.
- **Evidence Locations**:
  - **Memory Dump**: `C:\Users\johndoe\Desktop\memdump\PhysicalMemory.raw`
  - **Rapid Triage Artifacts**:
    - `C:\Users\johndoe\Desktop\kapefiles`
    - `C:\Users\johndoe\Desktop\files`
  - **Full Disk Image**: `C:\Users\johndoe\Desktop\fulldisk.raw.001`
  - **Parsed Disk Data**: `C:\Users\johndoe\Desktop\MalwareAttack`
  
### Notes
- Autopsy analysis should be done from `C:\Users\johndoe\Desktop\MalwareAttack`.
- Ideal forensics environment is separate from the impacted system; analysis is done directly on the affected system here for expediency.

---

## Memory Analysis with Volatility v3

### Identifying Memory Profile
To get OS and kernel details of the memory dump:
```shell
python vol.py -q -f ..\memdump\PhysicalMemory.raw windows.info
```
#### Sample Output
| Variable         | Value                                       |
|------------------|---------------------------------------------|
| Kernel Base      | 0xf80150019000                              |
| DTB              | 0x1ad000                                    |
| Symbols          | file:///C:/Users/johndoe/Desktop/...        |
| Is64Bit          | True                                        |
| SystemTime       | 2023-08-10 09:35:40                         |
| NtSystemRoot     | C:\Windows                                  |
| NtMajorVersion   | 10                                          |
| NtMinorVersion   | 0                                           |

### Detecting Injected Code
To find process memory regions potentially containing injected code:
```shell
python vol.py -q -f ..\memdump\PhysicalMemory.raw windows.malfind
```
#### Sample Output
Processes with `PAGE_EXECUTE_READWRITE` memory:
- `PID 3648` (rundll32.exe), `PID 6744` (powershell.exe), `PID 5468` (rundll32.exe)

#### Explanation of `PAGE_EXECUTE_READWRITE`
- This permission allows both execution and modification of code in memory, typically avoided in legitimate applications.
- Common with malware, which injects code into memory and executes it, warranting further investigation.

---

## Identifying Running Processes

### Listing Processes
Using `windows.pslist` to list processes:
```shell
python vol.py -q -f ..\memdump\PhysicalMemory.raw windows.pslist
```

#### Sample Output (Excerpt)
| PID   | PPID | ImageFileName     | CreateTime                | SessionId |
|-------|------|-------------------|---------------------------|-----------|
| 4     | 0    | System            | 2023-08-10 00:22:53.000000 | N/A       |
| 3648  | 7148 | rundll32.exe      | 2023-08-10 09:15:14.000000 | 1         |
| 6744  | 908  | powershell.exe    | 2023-08-10 09:21:16.000000 | 1         |
| 5468  | 7512 | rundll32.exe      | 2023-08-10 09:23:15.000000 | 0         |

### Viewing Process Tree
Using `windows.pstree` to view parent-child process relationships:
```shell
python vol.py -q -f ..\memdump\PhysicalMemory.raw windows.pstree
```
- Shows parent-child relationships, helping identify suspicious child processes spawned by common processes (e.g., rundll32.exe under explorer.exe).

---

## Identifying Process Command Lines

Using `windows.cmdline` to retrieve command-line arguments:
```shell
python vol.py -q -f ..\memdump\PhysicalMemory.raw windows.cmdline
```

#### Sample Output
| PID   | Process       | Args                                                                           |
|-------|---------------|--------------------------------------------------------------------------------|
| 416   | csrss.exe     | `%SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows ...`                  |
| 3648  | rundll32.exe  | `C:\Windows\System32\rundll32.exe payload.dll,StartW`                          |
| 6744  | powershell.exe | `PowerShell.exe -nop -w hidden -encodedcommand JABzAD0ATgBlAHcAL...`          |

---

## Dumping Process Memory & Leveraging YARA

To analyze process 3648, use Volatility's `windows.memmap` plugin to extract all memory-resident pages of this process:

```bash
python vol.py -q -f ../memdump/PhysicalMemory.raw windows.memmap --pid 3648 --dump
```

Sample output:
```plaintext
0xf8016d0e9000  0x2077d000      0x3000  0x1bde4000      pid.3648.dmp
... (continues with memory pages)
```

The memory dump `pid.3648.dmp` is stored at `c:\Users\johndoe\Desktop`.

## Scanning with YARA

Scan the memory dump with YARA rules using a PowerShell loop to apply all available rules from `https://github.com/Neo23x0/signature-base`.

PowerShell script:
```powershell
$rules = Get-ChildItem C:\Users\johndoe\Desktop\yara-4.3.2-2150-win64\rules | Select-Object -Property Name
foreach ($rule in $rules) {C:\Users\johndoe\Desktop\yara-4.3.2-2150-win64\yara64.exe C:\Users\johndoe\Desktop\yara-4.3.2-2150-win64\rules\$($rule.Name) C:\Users\johndoe\Desktop\pid.3648.dmp}
```

Sample output indicates hits for:
- `HKTL_CobaltStrike_Beacon_Strings`
- `CobaltStrike_Sleep_Decoder_Indicator`
- `WiltedTulip_ReflectiveLoader`

## Identifying Loaded DLLs

Examine loaded DLLs using the `windows.dlllist` plugin:
```bash
python vol.py -q -f ../memdump/PhysicalMemory.raw windows.dlllist --pid 3648
```

Output includes:
- `payload.dll` at `E:\payload.dll`, suggesting possible external or ISO origin.

## Identifying Handles

Use `windows.handles` to reveal accessed files and registry entries:
```bash
python vol.py -q -f ../memdump/PhysicalMemory.raw windows.handles --pid 3648
```

Sample output:
- Access to `\Device\HarddiskVolume3\Users\johndoe\Desktop`

## Identifying Network Artifacts

Analyze network connections with `windows.netstat`:
```bash
python vol.py -q -f ../memdump/PhysicalMemory.raw windows.netstat
```

Sample output reveals connections for:
- `chrome.exe`, `WWAHost.exe`, and `rundll32.exe`

For comprehensive network analysis, use:
```bash
python vol.py -q -f ../memdump/PhysicalMemory.raw windows.netscan
```
Sample output reveals:
- The suspicious process (PID `3648`) has been communicating with `44.214.212.249` over port `80`.

---


## Disk Image/Rapid Triage Data Examination & Analysis

### Searching for Keywords with Autopsy
- Open Autopsy and access the case at: `C:\Users\johndoe\Desktop\MalwareAttack`
- Search for `payload.dll`, prioritize by creation time.
- Significant finding: `Finance08062023.iso` in Downloads, related to `E` drive DLL.
- Extraction: Right-click on `Finance08062023.iso` and select **Extract File(s)**.

### Identifying Web Download Information & Extracting Files
- `.Zone.Identifier` via Alternate Data Stream (ADS) confirms internet origin.
- Source URL identified in Web Downloads artifacts as: `letsgohunt[.]site`.

### Analyzing Cobalt Strike Beacon Configuration
- Use `CobaltStrikeParser` at: `C:\Users\johndoe\Desktop\CobaltStrikeParser-master\CobaltStrikeParser-master`
- Command: `python parse_beacon_config.py E:\payload.dll`
- Key Configurations Extracted:
  - **BeaconType**: HTTP, **Port**: 80, **C2Server**: letsgohunt.site,/load
  - Other notable fields: `HttpGet_Metadata`, `bUsesCookies`, `Spawnto_x64`.

### Persistence Mechanisms with Autoruns
- Autoruns analysis: Check `C:\Users\johndoe\Desktop\files\johndoe_autoruns.arn`
- Found entry:
  - Path: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
  - Image: `C:\ProgramData\svchost.exe`

### File Hash Identification & VirusTotal
- To identify hash of `photo433.exe`:
  ```powershell
  PS C:\Users\johndoe> Get-FileHash -Algorithm SHA256 "C:\Users\johndoe\Desktop\kapefiles\auto\C%3A\Users\johndoe\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\photo443.exe"
  ```

### Scheduled Tasks & Timestomping Analysis
- Inconsistency between `$FILE_NAME MFT Modified` and `$STANDARD_INFORMATION File Modified` timestamps indicates timestomping.

### SRUM Data Analysis
- Observed potential exfiltration of `430526981` bytes from `SRUDB.dat`.

### Windows Event Logs Analysis with Chainsaw
- Command:
  ```
  C:\Users\johndoe>chainsaw_x86_64-pc-windows-msvc.exe hunt "..\kapefiles\auto\C%3A\Windows\System32\winevt\Logs" -s sigma/ --mapping mappings/sigma-event-logs-all.yml -r rules/ --csv --output output_csv
  ```
- Alerts observed in `sigma.csv`:
  - **Cobalt Strike Load by rundll32**
  - **UAC Bypass/Privilege Escalation by fodhelper.exe**

### Prefetch Files Analysis
- Command to analyze prefetch files:
  ```
  C:\Users\johndoe>C:\Users\johndoe\Desktop\Get-ZimmermanTools\net6\PECmd.exe -d "C:\Users\johndoe\Desktop\kapefiles\auto\C%3A\Windows\Prefetch" -q --csv C:\Users\johndoe\Desktop --csvf suspect_prefetch.csv
  ```

### USN Journal Analysis
- Command:
  ```
  C:\Users\johndoe>python C:\Users\johndoe\Desktop\files\USN-Journal-Parser-master\usnparser\usn.py -f C:\Users\johndoe\Desktop\kapefiles\ntfs\%5C%5C.%5CC%3A\$Extend\$UsnJrnl:$J -o C:\Users\johndoe\Desktop\usn_output.csv -c
  ```

Suspicious activities took place approximately between `2023-08-10 09:00:00` and `2023-08-10 10:00:00`.

To view the CSV using PowerShell in alignment with our timeline, we can execute:

```powershell
PS C:\Users\johndoe> $time1 = [DateTime]::ParseExact("2023-08-10 09:00:00.000000", "yyyy-MM-dd HH:mm:ss.ffffff", $null)
PS C:\Users\johndoe> $time2 = [DateTime]::ParseExact("2023-08-10 10:00:00.000000", "yyyy-MM-dd HH:mm:ss.ffffff", $null)
PS C:\Users\johndoe> Import-Csv -Path C:\Users\johndoe\Desktop\usn_output.csv | Where-Object { $_.'FileName' -match '\.exe$|\.txt$|\.msi$|\.bat$|\.ps1$|\.iso$|\.lnk$' } | Where-Object { $_.timestamp -as [DateTime] -ge $time1 -and $_.timestamp -as [DateTime] -lt $time2 }
```

---

Here's the full markdown for the content provided, formatted for clarity and utility in digital forensic analysis:

---

## Disk Image/Rapid Triage Data Examination & Analysis

### Analyzing Rapid Triage Data - MFT/pagefile.sys (MFTECmd/Autopsy)

#### Recovering Deleted Files Using MFT Analysis
1. **Objective**: Attempt to recover `flag.txt` via MFT analysis.
   - **Challenge**: The affected machine's MFT table is unavailable.
   - **Alternative**: Use another system’s MFT table (`C:\Users\johndoe\Desktop\files\mft_data`), where `flag.txt` was similarly deleted.

2. **Run MFTECmd** to parse the $MFT file:
   ```plaintext
   C:\Users\johndoe> C:\Users\johndoe\Desktop\Get-ZimmermanTools\net6\MFTECmd.exe -f C:\Users\johndoe\Desktop\files\mft_data --csv C:\Users\johndoe\Desktop\ --csvf mft_csv.csv
   ```
   - **Output**:
     - Processed MFT file with **113,899** records (4,009 marked as free).
     - **CSV output** saved at `C:\Users\johndoe\Desktop\mft_csv.csv`.

3. **Search for flag.txt**:
   ```powershell
   PS C:\Users\johndoe> Select-String -Path C:\Users\johndoe\Desktop\mft_csv.csv -Pattern "flag.txt"
   ```
   - **Result**:
     - Provides `flag.txt`'s location: `\Users\johndoe\Desktop\reports`.

4. **Verify with MFT Explorer**:
   - **Tool**: Open `C:\Users\johndoe\Desktop\files\mft_data` in MFT Explorer (available at `C:\Users\johndoe\Desktop\Get-ZimmermanTools\net6\MFTExplorer`).
   - **Finding**: Within the `reports` folder, `flag.txt` is marked with the **Is deleted** attribute.

#### Understanding NTFS File Deletion
- **Insight**:
   - Deleted files on NTFS volumes have MFT entries marked as free, making recovery possible until the data is overwritten.
   - **Case-Specific**: The compromised system’s file was overwritten, necessitating MFT analysis on another system.

#### Extracting Data from pagefile.sys
1. **Scenario**: Portions of `flag.txt` remain in `pagefile.sys`, which Windows uses to manage RAM overflow.
2. **Approach**:
   - Use **Autopsy** to scan `pagefile.sys` for partial content recovery.

### Constructing an Execution Timeline with Autopsy

1. **Timeline Parameters**:
   - **Incident Window**: 09:13 to 09:30 (GMT / UTC).
   - **Tool**: Autopsy, leveraging Plaso for timeline generation.
   
2. **Configuration**:
   - **Event Types**: Select `Web Activity: All` and `Other: All`.
   - **Time Settings**:
     - Start: `Aug 10, 2023, 9:13:00 AM`
     - End: `Aug 10, 2023, 9:30:00 AM`

3. **Purpose**:
   - To map the chronological actions of the malicious actor by filtering files accessed or created during this interval.

### The Actual Attack Timeline
- **Objective**: Examine identified and undetected actions taken by the attacker.
- **Next Step**: Based on forensic findings, try to match documented activity with any undetected actions outlined in the actual attack sequence.


![[Pasted image 20241109093825.png]]
![[Pasted image 20241109093835.png]]