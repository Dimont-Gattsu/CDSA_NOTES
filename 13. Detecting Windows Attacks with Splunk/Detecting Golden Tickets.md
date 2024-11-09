### Splunk Query for Detecting Golden Tickets

The query below is designed to flag suspicious Kerberos activity, specifically identifying situations where TGS (Ticket Granting Service) tickets are being requested without the usual AS-REQ and AS-REP steps. This pattern suggests that an attacker may have forged a TGT, allowing them to directly request service tickets.

```spl
index="golden_ticket_attack" sourcetype="bro:kerberos:json"
| where client!="-"
| bin _time span=1m 
| stats values(client), values(request_type) as request_types, dc(request_type) as unique_request_types by _time, id.orig_h, id.resp_h
| where request_types=="TGS" AND unique_request_types==1
```

### Query Breakdown

1. **Data Selection**:
   - `index="golden_ticket_attack" sourcetype="bro:kerberos:json"`: Searches within the specified index for logs in `bro:kerberos:json` format, which represents Kerberos events from Zeek.
   
2. **Client Filtering**:
   - `| where client!="-“`: Excludes events where the `client` field is blank (`"-"`), which filters out irrelevant events lacking client information and minimizes noise.

3. **Time Binning**:
   - `| bin _time span=1m`: Groups events into one-minute intervals based on `_time`, the event timestamp, to detect patterns of rapid ticket requests within these short windows.

4. **Aggregating Statistics**:
   - `| stats values(client), values(request_type) as request_types, dc(request_type) as unique_request_types by _time, id.orig_h, id.resp_h`: Aggregates data by:
     - `_time`: The timestamp (by minute).
     - `id.orig_h`: Source IP (the client making the request).
     - `id.resp_h`: Destination IP (typically the Domain Controller).
   - **Field Calculations**:
     - `values(client)`: Lists unique clients associated with the events.
     - `values(request_type) as request_types`: Captures all unique Kerberos request types observed within each time interval.
     - `dc(request_type) as unique_request_types`: Counts distinct Kerberos request types to check for diversity in request types (an indicator of normal Kerberos activity).
   
5. **Filtering for Golden Ticket Behavior**:
   - `| where request_types=="TGS" AND unique_request_types==1`: Isolates cases where:
     - The only request type is `TGS`, indicating direct access to service tickets without preceding AS-REQ/AS-REP steps.
     - `unique_request_types==1`, confirming no other request types are present, reinforcing suspicion of a Golden Ticket or similar attack that skips the typical Kerberos authentication steps.

### Interpretation

- **What It Flags**:
  - This query will flag any instances where a client makes only `TGS` requests within a minute interval, with no evidence of `AS-REQ` or other Kerberos request types. This behavior is atypical, as legitimate users generally initiate Kerberos authentication with an `AS-REQ` to obtain a TGT.
  - By identifying such patterns, we can highlight possible Golden Ticket attacks where an attacker forges a TGT to bypass initial authentication, directly requesting service tickets instead.

- **What to Investigate**:
  - **Source IP and Client Information**: Look into the client (`id.orig_h`) making the requests to verify whether they’re a known user or a potentially compromised machine.
  - **Repetitive Patterns**: Multiple consecutive intervals with only TGS requests from the same client can reinforce suspicion of malicious intent.
  - **Anomalous Destination IPs**: Destination addresses (`id.resp_h`) that don’t typically interact with the source may indicate an unauthorized service request.