## Overview

Kerberos brute force attacks involve attackers sending a large volume of AS-REQ (Authentication Service Request) messages to the Key Distribution Center (KDC) with different usernames, hoping to determine valid accounts based on the KDC’s responses. These attempts are often characterized by failed authentication requests with specific error messages that reveal the validity of usernames without fully authenticating.

In this Splunk search, we identify Kerberos brute force attempts by monitoring patterns in Zeek logs that indicate repeated authentication failures, particularly those that do not return the common preauthentication-required response. 

---

## Splunk Query for Detecting Kerberos Brute Force

The following query focuses on failed AS-REQ attempts in a short time frame to help identify potential brute force activities. By setting a threshold of more than 30 requests within a 5-minute interval, we can flag unusual patterns that suggest brute force attempts.

### Query Breakdown

```spl
index="kerberos_bruteforce" sourcetype="bro:kerberos:json"
error_msg!=KDC_ERR_PREAUTH_REQUIRED
success="false" request_type=AS
| bin _time span=5m
| stats count dc(client) as "Unique users" values(error_msg) as "Error messages" by _time, id.orig_h, id.resp_h
| where count>30
```

### Detailed Steps:

1. **Select the Relevant Data Source**:
   - `index="kerberos_bruteforce"` specifies the index where Zeek logs for Kerberos brute force activities are stored.
   - `sourcetype="bro:kerberos:json"` specifies that the source type is Zeek JSON logs specifically for Kerberos activity.

2. **Filter for Non-Preauthentication Errors**:
   - `error_msg!=KDC_ERR_PREAUTH_REQUIRED` excludes events with the `KDC_ERR_PREAUTH_REQUIRED` error message, which is a standard response indicating valid usernames. This helps focus on requests that failed without requiring preauthentication, which could indicate attempts with invalid usernames.

3. **Filter for Failed AS-REQ Requests**:
   - `success="false"` and `request_type=AS` filters the search to only include unsuccessful Authentication Service requests (AS-REQ), which represent login attempts that failed to authenticate.

4. **Time-Binning Events**:
   - `| bin _time span=5m` groups events into 5-minute intervals, enabling us to detect high volumes of authentication requests within short periods, a common sign of brute force attempts.

5. **Count Failed Requests and Track Unique Users**:
   - `| stats count dc(client) as "Unique users" values(error_msg) as "Error messages" by _time, id.orig_h, id.resp_h`:
      - `count`: Counts the number of failed attempts for each source-destination pair within each time interval.
      - `dc(client) as "Unique users"`: Counts the distinct usernames targeted.
      - `values(error_msg) as "Error messages"`: Lists error messages associated with the failures to identify patterns in error responses.
      - `_time, id.orig_h, id.resp_h`: Groups these statistics by time intervals and IP addresses of the client (`id.orig_h`) and the KDC (`id.resp_h`).

6. **Set a Threshold for Flagging Brute Force Activity**:
   - `| where count>30` filters the results to show only cases where there are more than 30 failed attempts within a 5-minute interval, which is suspicious and suggests potential brute force activity.

---

### Interpreting Results

- **High Failed Attempt Counts**: Cases with more than 30 failed attempts from a single source IP within 5 minutes, especially with distinct usernames, indicate potential brute force attempts.
- **Error Message Patterns**: Reviewing error messages helps differentiate between valid and invalid usernames, which is valuable in identifying user enumeration efforts.
- **Threshold Adjustments**: The `count>30` threshold may be adjusted depending on the environment to reduce false positives, as lower values might flag legitimate activity.