## Overview

Kerberoasting is an attack technique in which an attacker with valid domain credentials requests Service Principal Name (SPN) tickets. These tickets, often encrypted using RC4, can be cracked offline to reveal plaintext credentials for service accounts. The main detection point for Kerberoasting is identifying unusual TGS (Ticket Granting Service) requests, especially those using the RC4 cipher, since attackers typically leverage it for offline cracking.

---

## Splunk Query for Detecting Kerberoasting

The following query helps identify suspicious Kerberos ticket-granting service requests that indicate possible Kerberoasting activity. This search filters for TGS requests using the RC4 cipher, often configured for service accounts in Kerberoasting attacks.

### Query Breakdown

```spl
index="sharphound" sourcetype="bro:kerberos:json"
request_type=TGS cipher="rc4-hmac" 
forwardable="true" renewable="true"
| table _time, id.orig_h, id.resp_h, request_type, cipher, forwardable, renewable, client, service
```

### Detailed Steps:

1. **Select the Relevant Data Source**:
   - `index="sharphound"` specifies the index where logs related to the Kerberoasting activity are stored.
   - `sourcetype="bro:kerberos:json"` specifies that the logs are from Zeek, specifically in JSON format for Kerberos events.

2. **Filter for TGS Requests Using RC4 Cipher**:
   - `request_type=TGS`: Filters the search to include only TGS (Ticket Granting Service) requests, which are specifically targeted in Kerberoasting attacks.
   - `cipher="rc4-hmac"`: Limits results to requests where the RC4 cipher is used for ticket encryption. Attackers favor RC4 because it can be cracked offline, given its relative weakness compared to other encryption methods.

3. **Check for Forwardable and Renewable Tickets**:
   - `forwardable="true"` and `renewable="true"`: These attributes often indicate tickets associated with service accounts, making them prime targets for Kerberoasting. Forwardable tickets allow the use of the ticket across different services, and renewable tickets can be refreshed, attributes attackers might leverage.

4. **Format the Results**:
   - `| table _time, id.orig_h, id.resp_h, request_type, cipher, forwardable, renewable, client, service`: Selects key fields for easy review, including:
      - `_time`: The timestamp of the event.
      - `id.orig_h`: Source IP address of the request.
      - `id.resp_h`: Destination IP address (typically the Domain Controller handling the request).
      - `client`: The account making the request.
      - `service`: The service account for which the TGS request was made, which can be targeted for offline cracking.

---

### Interpreting Results

- **Frequent RC4 TGS Requests**: Look for repeated TGS requests using the RC4 cipher. An unusually high volume of such requests from a single user or system can indicate Kerberoasting activity.
- **Forwardable and Renewable Tickets**: These tickets are particularly useful for attackers in lateral movement, as they allow tickets to be used across services and renewed as needed.