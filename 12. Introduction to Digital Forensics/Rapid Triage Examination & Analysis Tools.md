## Download and Setup
- Use the `.net 4` or `.net 6` link on the website for downloads.
- Alternatively, utilize PowerShell:
  ```
  PS C:\Users\johndoe\Desktop\Get-ZimmermanTools> .\Get-ZimmermanTools.ps1
  ```
  - Downloads all tools to `C:\htb\dfir_module\tools`.
  - Tracks SHA-1 for easy updates.

## MAC(b) Times in NTFS
**MAC(b)** times track file system events:
- **Modified Time (M)**: Last content modification.
- **Accessed Time (A)**: Last access time.
- **Changed (C)**: Reflects MFT changes.
- **Birth Time (b)**: Original creation time.

### Example Commands
- **MFTECmd to Inspect $MFT Files**:
  ```
  PS C:\Users\johndoe\Desktop\Get-ZimmermanTools\net6> .\MFTECmd.exe -f 'C:\Users\johndoe\Desktop\forensic_data\kape_output\D\$MFT' --de 0x16169
  ```

## Investigation Tools Overview

### MFT File Structure
- Master File Table (MFT) is crucial in tracking files on NTFS.
- **Attributes in MFT** include `$STANDARD_INFORMATION` and `$FILE_NAME`.

### Windows Event Logs
- **EvtxECmd** for parsing EVTX logs to CSV or JSON:
  ```
  PS C:\Users\johndoe\Desktop\Get-ZimmermanTools\net6\EvtxeCmd> .\EvtxECmd.exe -f "path\to\log.evtx" --csv "output_path"
  ```
- **Event Query Language (EQL)** for querying JSON-formatted logs.

### Windows Registry Analysis
- **RegRipper** extracts specific data via plugins:
  ```
  PS C:\Users\johndoe\Desktop\RegRipper3.0-master> .\rip.exe -r "C:\path\to\hive" -p plugin_name
  ```
- **Registry Explorer** provides GUI access.

### Program Execution Artifacts
1. **Prefetch Analysis** with **PECmd**:
   ```
   PS C:\Users\johndoe\Desktop\Get-ZimmermanTools\net6> .\PECmd.exe -f C:\path\to\prefetch_file.pf
   ```
2. **ShimCache and Amcache**: Access with Registry Explorer for program history.

### Advanced Analysis
- **PowerShell Transcripts**: Review unusual PowerShell commands.
- **API Monitoring**: `getenv`, `CreateProcessA`, and `RegOpenKeyExA` show interaction details.

## Key Commands for Forensic Analysis

### PowerShell Commands
- Check network-related commands, encoded commands, and unusual modules.

### Other Important Scripts and Commands
- **EQL JSON format creation**:
  ```
  PS C:\Users\eqllib-master\utils> Get-WinEvent -Path "log_path" -Oldest | Get-EventProps | ConvertTo-Json
  ```