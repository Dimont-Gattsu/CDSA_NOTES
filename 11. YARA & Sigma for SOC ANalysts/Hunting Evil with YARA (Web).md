## Overview

**Unpac.Me** offers a robust solution for malware unpacking and enables Security Analysts to run YARA rules over a vast database of malware submissions. This platform provides access to a commercial-grade malware dataset, making it a valuable resource for SOC analysts and malware researchers.

## Testing YARA Rules with Unpac.Me

For example, let's consider the following YARA rule targeting Dharma ransomware:

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

### Steps for Running a YARA Hunt on Unpac.Me

1. **Register**: Sign up for a free account on Unpac.Me.
2. **Start a New Hunt**:
   - Navigate to **Yara Hunt** and select **New Hunt**.
   - Paste the YARA rule into the rule entry field.
3. **Validate and Scan**:
   - Click **Validate** to ensure the rule is correct, then **Scan**.
4. **Review Results**: After scanning, Unpac.Me displays results, showing matches within minutes.
