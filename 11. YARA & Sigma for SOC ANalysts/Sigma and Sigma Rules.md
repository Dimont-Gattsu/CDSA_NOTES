
## Overview

Sigma is a generic and standardized signature format that enables SOC analysts to create, share, and utilize detection rules for log analysis across different platforms. Written in YAML, Sigma rules offer cross-platform portability, allowing analysts to write a rule once and deploy it across various SIEM and EDR systems. 

## Key Use Cases for Sigma Rules

1. **Universal Log Analytics**: Write detection rules once and convert them to various SIEM formats.
2. **Community Rule Sharing**: Access and contribute to a growing library of community-shared Sigma rules.
3. **Incident Response**: Efficiently search logs for specific indicators during incidents.
4. **Proactive Threat Hunting**: Use Sigma rules to find anomalies or threats within datasets.
5. **Integration with Automation Tools**: Automate responses by using Sigma rules with SOAR platforms.
6. **Customization**: Tailor Sigma rules to specific environment needs.
7. **Gap Analysis**: Perform gap analysis by aligning custom rules with community standards.

## How Sigma Works

Sigma expresses detection patterns in a structured format, with rules written in YAML. Sigma rules consist of:
- **Title, Description, and ID**: Basic rule information.
- **Log Source**: Specifies the target log type, platform, and application.
- **Detection Pattern**: Includes search identifiers and conditions for matching.
- **False Positives, Author, and Date**: Optional fields for context.

### Sigma Conversion (sigmac & pySigma)

Sigma’s power lies in its convertibility. Tools like `sigmac` (and increasingly `pySigma`) transform Sigma rules into queries or configurations compatible with popular SIEMs (ElasticSearch, QRadar, Splunk, etc.).

## Sigma Rule Structure

Sigma rules are YAML files with structured fields. Below is an example Sigma rule format.

```yaml
title: Potential LethalHTA Technique Execution 
id: ed5d72a6-f8f4-479d-ba79-02f6a80d7471 
status: test 
description: Detects potential LethalHTA technique where "mshta.exe" is spawned by an "svchost.exe" process
references:
    - https://codewhitesec.blogspot.com/2018/07/lethalhta.html
author: Markus Neis 
date: 2018/06/07 
tags: 
    - attack.defense_evasion 
    - attack.t1218.005 
logsource: 
    category: process_creation  
    product: windows
detection:
    selection: 
        ParentImage|endswith: '\svchost.exe'
        Image|endswith: '\mshta.exe'
    condition: selection
falsepositives: 
    - Unknown
level: high
```

### Key Components of a Sigma Rule

1. **Title**: Describes the detection focus (e.g., "Potential LethalHTA Technique Execution").
2. **ID**: Unique identifier (UUID recommended).
3. **Status**: Status of the rule (e.g., stable, test, experimental).
4. **Description**: Brief explanation of what the rule detects.
5. **References**: Links to supporting articles or research.
6. **Author**: Rule creator’s name or handle.
7. **Date**: Creation date in YYYY/MM/DD format.
8. **Log Source**: Specifies the log source and platform (e.g., `category: process_creation`, `product: windows`).
9. **Detection Pattern**:
    - **Selection**: Specifies the patterns to match in logs.
    - **Condition**: Describes the relationship between patterns (e.g., `condition: selection`).

### Detection Modifiers
Modifiers refine detection searches:
- **contains**: Wildcards on both ends of a value (e.g., `CommandLine|contains`).
- **startswith** / **endswith**: Wildcards on one end.
- **re**: Regex-based matching.

Example modifiers in use:

```yaml
detection:
  selection:
    ParentImage|endswith: '\svchost.exe'
    Image|endswith: '\mshta.exe'
  condition: selection
```

## Sigma Rule Development Best Practices

Sigma’s [Rule Creation Guide](https://github.com/SigmaHQ/sigma/wiki/Specification) provides best practices for rule development, including detailed information on structuring and writing effective detection rules.

### Common Operators in Conditions

Sigma conditions link detection elements, supporting operators like:
- `and` / `or`: Logical conjunctions.
- `all of them`: Matches all patterns.
- `not`: Excludes certain matches.
- Brackets `()`: Enforces operation order.

Example condition:
```yaml
condition: selection1 or selection2 or selection3
```
