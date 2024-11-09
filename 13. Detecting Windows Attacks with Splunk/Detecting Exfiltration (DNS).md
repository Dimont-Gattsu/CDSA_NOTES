### Splunk Query for Detecting DNS Exfiltration

```spl
index=dns_exf sourcetype="bro:dns:json"
| eval len_query=len(query)
| search len_query>=40 AND query!="*.ip6.arpa*" AND query!="*amazonaws.com*" AND query!="*._googlecast.*" AND query!="_ldap.*"
| bin _time span=24h
| stats count(query) as req_by_day by _time, id.orig_h, id.resp_h
| where req_by_day>60
| table _time, id.orig_h, id.resp_h, req_by_day
```

### Query Breakdown

1. **Selecting Relevant Data**:
   - `index=dns_exf sourcetype="bro:dns:json"`: Filters data to focus on DNS logs (in `bro:dns:json` format) in the `dns_exf` index, where suspected DNS exfiltration activities are logged.

2. **Calculating Query Length**:
   - `| eval len_query=len(query)`: Calculates the length of each DNS query string, storing it in a new field called `len_query`. This length is used to detect unusually long DNS queries, which may indicate data embedded within the DNS request.

3. **Filtering by Query Length and Excluding Common Domains**:
   - `| search len_query>=40 AND query!="*.ip6.arpa*" AND query!="*amazonaws.com*" AND query!="*._googlecast.*" AND query!="_ldap.*"`: 
     - Filters out DNS queries shorter than 40 characters and excludes common, benign domains and reverse lookups (e.g., `ip6.arpa`, `amazonaws.com`, `googlecast`, and `_ldap`). 
     - Queries longer than 40 characters are often a sign of encoded or encrypted data embedded within the DNS requests.

4. **Grouping Data by 24-Hour Intervals**:
   - `| bin _time span=24h`: Groups the events into 24-hour time intervals, allowing for daily analysis of query volume.

5. **Counting Queries by Day and Identifying High-Volume Sources**:
   - `| stats count(query) as req_by_day by _time, id.orig_h, id.resp_h`: Aggregates the total number of DNS requests per day (`req_by_day`) by source IP (`id.orig_h`) and destination IP (`id.resp_h`) in each 24-hour interval.

6. **Flagging Unusual Activity**:
   - `| where req_by_day>60`: Filters results to show only cases where the daily query count exceeds 60, as high-frequency queries can indicate DNS-based data exfiltration.

7. **Output Table**:
   - `| table _time, id.orig_h, id.resp_h, req_by_day`: Displays the timestamp (`_time`), source IP (`id.orig_h`), destination IP (`id.resp_h`), and daily request count (`req_by_day`) in a table format for easy analysis.