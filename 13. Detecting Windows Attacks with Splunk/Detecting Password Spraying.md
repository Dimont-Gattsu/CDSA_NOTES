## Overview

**Password Spraying** is a targeted attack that:
- Attempts a limited number of commonly used passwords across multiple user accounts.
- Avoids account lockout policies by using only a few password attempts per account.
- Is designed to evade detection by exploiting weak passwords across a wide user base rather than brute-forcing individual accounts.

**Example**: Password spraying via the Spray tool, where the attacker tests a limited set of passwords across multiple accounts in a network.

---

## Detection Opportunities

### Log-Based Indicators of Password Spraying

Monitoring Windows logs for patterns of password spraying can reveal anomalies, especially when multiple failed logon attempts (Event ID 4625) from different user accounts originate from a single IP address over a short period.

Key Event Logs for Password Spraying Detection:

1. **4625** - Failed Logon
   - Tracks failed logins for different accounts from a single source.
2. **4768** - Kerberos Authentication Ticket (TGT) Request
   - ErrorCode 0x6: Invalid user attempts.
   - ErrorCode 0x12: Disabled user attempts.
3. **4776** - NTLM Authentication
   - ErrorCode 0xC000006A: NTLM invalid users.
   - ErrorCode 0xC0000064: NTLM wrong password.
4. **4648** - Logon Attempt Using Explicit Credentials
   - Identifies credential misuse.
5. **4771** - Kerberos Pre-Authentication Failure

---

## Detecting Password Spraying Using Splunk

### Timeframe

- **Earliest**: `1690280680`
- **Latest**: `1690289489`

### Splunk Query

```spl
index=main earliest=1690280680 latest=1690289489 source="WinEventLog:Security" EventCode=4625
| bin span=15m _time
| stats values(user) as Users, dc(user) as dc_user by src, Source_Network_Address, dest, EventCode, Failure_Reason
```

### Query Breakdown

1. **Filter by Index, Source, and Event Code**:
   - Focuses on the Security Event Log entries (`WinEventLog:Security`) with `EventCode=4625`, representing failed logons.
  
2. **Time Range Filter**:
   - Limits search to a specific timeframe based on Unix timestamps, filtering only relevant logs.
  
3. **Time Binning**:
   - The `bin` command groups events into 15-minute intervals, aiding in pattern detection by observing failed logon attempts over short time spans.

4. **Statistics Aggregation**:
   - The `stats` command aggregates by key fields to analyze logon failures across different accounts.
     - `values(user) as Users`: Lists all unique users associated with failed logon attempts.
     - `dc(user) as dc_user`: Counts distinct users within each group to identify multiple accounts targeted from a single IP source.