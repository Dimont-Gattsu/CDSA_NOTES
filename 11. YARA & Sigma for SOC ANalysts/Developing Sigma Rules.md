## Overview

This guide walks through creating Sigma rules manually, using real-world examples to detect suspicious activities.

### Example 1: Detecting LSASS Credential Dumping
In this scenario, the `shell.exe` process (mimikatz) attempts to access `lsass.exe` memory. Sysmon Event ID 10 logs this activity when `shell.exe` tries to access the LSASS memory, capturing it in event logs.

#### Relevant Information
- **Sysmon Event ID**: 10
- **Critical Fields**: 
  - `TargetImage`: Specifies the target process (e.g., `lsass.exe`)
  - `GrantedAccess`: Specific permissions, commonly `0x1010` (read and query access)

### LSASS Credential Dumping Detection Rule
```yaml
title: LSASS Access with rare GrantedAccess flag 
status: experimental
description: Detects process access to LSASS memory with suspicious access flag 0x1010
date: 2023/07/08
tags:
    - attack.credential_access
    - attack.t1003.001
logsource:
    category: process_access
    product: windows
detection:
    selection:
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess|endswith: '0x1010'
    condition: selection
```

#### Explanation
1. **Title**: Clearly describes the rule's purpose.
2. **Status**: Indicates it’s still in testing.
3. **Detection Criteria**:
   - **TargetImage**: Matches logs where the target process ends with `lsass.exe`.
   - **GrantedAccess**: Ensures the access flag is `0x1010`.
   - **Condition**: Triggers if the criteria in `selection` are met.

#### Running the Rule with sigmac
To convert the Sigma rule into a PowerShell query:
```powershell
python sigmac -t powershell 'C:\Rules\sigma\proc_access_win_lsass_access.yml'
```

#### Robust Rule: Adding Filters for Suspicious Paths and False Positives
A more advanced version includes filtering out common false positives:
```yaml
title: LSASS Access From Program in Potentially Suspicious Folder
id: fa34b441-961a-42fa-a100-ecc28c886725
status: experimental
description: Detects process access to LSASS memory with suspicious access flags and from a potentially suspicious folder
tags:
    - attack.credential_access
    - attack.t1003.001
logsource:
    category: process_access
    product: windows
detection:
    selection:
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess|endswith:
            - '10'
            - '30'
            - '50'
            - '70'
            - '90'
            - 'B0'
            - 'D0'
            - 'F0'
    SourceImage|contains:
            - '\Temp\'
            - '\Users\Public\'
    condition: selection and not 1 of filter_optional_*
```

### Example 2: Detecting Multiple Failed Logins from Single Source
Event ID 4776 logs credential validation attempts. When multiple failed attempts are observed from a single workstation, it may indicate an attempted breach.

```yaml
title: Failed NTLM Logins with Different Accounts from Single Source System
id: 6309ffc4-8fa2-47cf-96b8-a2f72e58e538
logsource:
    product: windows
    service: security
detection:
    selection2:
        EventID: 4776
        TargetUserName: '*'
        Workstation: '*'
    condition: selection2 | count(TargetUserName) by Workstation > 3
```

#### Explanation
- **Logsource**: Focuses on Windows Security logs.
- **Detection**: Filters for Event ID 4776 and counts instances of `TargetUserName` by `Workstation`.
- **Condition**: Flags if a single source attempts more than three logins with different accounts.

## Sigma Rule Development Resources

The following links provide additional guidance and best practices for Sigma rule development:
- Official Documentation: https://github.com/SigmaHQ/sigma/wiki/Rule-Creation-Guide
- Specification: https://github.com/SigmaHQ/sigma-specification
- Sigma Development Articles: https://tech-en.netlify.app/articles/en510480/

