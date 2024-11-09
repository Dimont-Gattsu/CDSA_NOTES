## What is Active Directory?
Active Directory (AD) is Microsoft’s directory service for Windows enterprise environments, first released in 2000 with Windows Server 2000. Built on x.500 and LDAP protocols, AD supports centralized management of resources including users, computers, groups, and network devices, along with access management and group policies.

AD is widely used as the primary Identity and Access Management (IAM) solution in enterprises. A compromise of AD results in full access to all systems and data within the domain, representing a critical security risk if vulnerabilities are exploited.

### Key Concepts

- **Domain**: A group of objects sharing the same AD database (e.g., users, devices).
- **Tree**: Group of one or more domains (e.g., `test.local`, `staging.test.local`).
- **Forest**: Collection of multiple trees, representing the highest hierarchical level.
- **Organizational Unit (OU)**: Containers holding user groups, computers, and other OUs.
- **Trust**: Relationship allowing access to resources across domains.
- **Domain Controller**: The highest authority in AD, managing authentication and authorization.
- **Active Directory Data Store**: Contains files like NTDS.DIT, storing directory information.

### Core Protocols and Authentication in AD

- **LDAP**: Protocol for querying and modifying AD data.
- **Authentication Methods**:
	- **Username/Password**: Stored/transmitted as hashes (LM, NTLM, etc.).
	- **Kerberos Tickets**: Tokens for authenticated access using cryptographic proof of identity.
	- **LDAP Authentication**: Via username/password or certificates.
	- **Key Distribution Center (KDC)**: The Kerberos service generating tickets.

### Default Privileged Groups in AD
AD includes highly privileged groups like **Domain Admins** and **Enterprise Admins**. These groups grant broad access rights across domain-joined machines and within the forest. Mismanagement of these groups can lead to serious security risks.

### Logon Types
Windows supports multiple logon types, which affect credential traces left on systems. Logon types except for Network logon (type 3) leave credentials behind.

### Tools for Managing Active Directory
AD interaction is enabled by tools like **Remote Server Administration Tools (RSAT)** and interfaces like **Active Directory Users and Computers** and **Group Policy Management Console**.

### Important Ports in AD Environments
- **53**: DNS
- **88**: Kerberos
- **135**: WMI/RPC
- **137-139, 445**: SMB
- **389, 636**: LDAP
- **3389**: RDP
- **5985, 5986**: PowerShell Remoting (WinRM)

## Real-world Implications of AD Security
Active Directory plays a pivotal role in enterprise environments, managing services like DNS, PKI, and Endpoint Configuration. If these services are compromised, an attacker could escalate privileges to control the forest. To reduce risks, organizations must classify and monitor additional services added to AD.

## AD Limitations and Attack Surface

- **Complexity**: Example - Nested group memberships can create convoluted privilege chains.
- **Design**: AD’s use of Group Policy Objects (GPOs) relies on SYSVOL shared folders, accessible via SMB. With privileged credentials, attackers could remotely execute code on Domain Controllers over SMB.
- **Legacy Protocols**: Windows uses legacy protocols like NetBIOS and LLMNR by default, which can broadcast credentials on the network, exposing them to potential capture.

Active Directory remains central to enterprise IAM, but its complexity, design, and reliance on legacy protocols demand robust security practices, including segmentation, defense-in-depth, and continuous monitoring to prevent and detect unauthorized access.
