## Overview

Using YARA on Windows systems is effective for identifying threats on disk and in memory.

1. **Connect to Target System**: 
   - Launch the target system.
   - Use RDP to connect with provided credentials.

## Hunting for Malicious Executables on Disk

- **Sample File**: `dharma_sample.exe` located in `C:\Samples\YARASigma`.
- **Hex Analysis**: Using HxD to inspect strings like `C:\crysis\Release\PDB\payload.pdb` and `sssssbsss`.
- **YARA Rule Example**: Detecting patterns in malicious executables.

```yara
rule ransomware_dharma {
    meta:
        author = "Madhukar Raina"
        version = "1.0"
        description = "Detect strings from Dharma ransomware"
        reference = "https://www.virustotal.com"

    strings:
        $string_pdb = { 433A5C6372797369735C52656C656173655C5044425C7061796C6F61642E706462 }
        $string_ssss = { 73 73 73 73 73 62 73 73 73 }

    condition: all of them
}
```

### Command to Execute YARA Scan on Files

```powershell
yara64.exe -s C:\Rules\yara\dharma_ransomware.yar C:\Samples\YARASigma\ -r 2>null
```

- **Detected Files**: `pdf_reader.exe`, `microsoft.com`, `check_updates.exe`, `KB5027505.exe`.

## Hunting for Malware in Running Processes

- **Target Process**: Example with `meterpreter` shellcode injection.
- **YARA Rule for Metasploit Meterpreter**:

```yara
rule meterpreter_reverse_tcp_shellcode {
    meta:
        author = "FDD @ Cuckoo sandbox"
        description = "Metasploit meterpreter reverse tcp shellcode"

    strings:
        $s1 = { fce8 8?00 0000 60 }
        $s2 = { 648b ??30 }
        $s3 = { 4c77 2607 }
        $s4 = "ws2_"
        $s5 = { 2980 6b00 }
        $s6 = { ea0f dfe0 }
        $s7 = { 99a5 7461 }

    condition: 5 of them
}
```

### Scanning Active Processes

```powershell
Get-Process | ForEach-Object { "Scanning with Yara for meterpreter shellcode on PID "+$_.id; & "yara64.exe" "C:\Rules\yara\meterpreter_shellcode.yar" $_.id }
```

- **Result**: Detects shellcode in process PID 9084.

## Hunting for Evil Within ETW Data with YARA

### Key ETW Providers
- **Microsoft-Windows-Kernel-Process**: Tracks process activities.
- **Microsoft-Windows-Kernel-File**: Monitors file operations.
- **Microsoft-Windows-DNS-Client**: Logs DNS activity (useful for C2 detection).
  
### YARA and SilkETW Integration Example

1. **PowerShell ETW Provider**:

    ```powershell
    .\SilkETW.exe -t user -pn Microsoft-Windows-PowerShell -ot file -p ./etw_ps_logs.json -l verbose -y C:\Rules\yara -yo Matches
    ```

    - **YARA Rule for PowerShell Strings**:

    ```yara
    rule powershell_hello_world_yara {
        strings:
            $s0 = "Write-Host" ascii wide nocase
            $s1 = "Hello" ascii wide nocase
            $s2 = "from" ascii wide nocase
            $s3 = "PowerShell" ascii wide nocase
        condition: 3 of ($s*)
    }
    ```

2. **DNS Client Provider**:

    ```powershell
    .\SilkETW.exe -t user -pn Microsoft-Windows-DNS-Client -ot file -p ./etw_dns_logs.json -l verbose -y C:\Rules\yara -yo Matches
    ```

    - **YARA Rule for Wannacry Domain**:

    ```yara
    rule dns_wannacry_domain {
        strings:
            $s1 = "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii wide nocase
        condition: $s1
    }
    ```