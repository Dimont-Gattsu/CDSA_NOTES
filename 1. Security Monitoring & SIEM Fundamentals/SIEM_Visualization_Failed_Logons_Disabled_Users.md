## Objective
Create a visualization to monitor failed login attempts specifically for disabled users in a Windows environment.

## Steps

1. **Navigate to the Target System**  
   - Access the SIEM tool via `http://[Target IP]:5601`.
   - Open the "Dashboard" by toggling the side navigation and selecting it.

2. **Edit Dashboard**  
   - Click the "pencil" or edit icon to modify the dashboard.
   - Click on "Create visualization" to start the process.

3. **Configure Visualization Settings**
   - **Filter Configuration**  
     - Set up a filter to focus on event ID `4625`, representing failed logon attempts.
     - Use the `winlog.event_data.SubStatus` field with a value of `0xC0000072` to identify failures due to disabled user logins.
   - **Index Pattern**  
     - Specify `windows*` as the index pattern to ensure Windows-related logs are used.
   - **Search Bar Check**  
     - Verify the `user.name.keyword` field is present in the dataset to confirm access to accurate data.
   - **Choose Visualization Type**  
     - From the drop-down menu, select the "Table" visualization type.

4. **Table Configuration**
   - **Rows Settings**  
     - Add "Rows" and include relevant data elements.
     - Configure the table to display:
       - **Disabled User** - the user account associated with the failed attempt.
       - **Machine** - the host machine reporting the event, using the `host.hostname.keyword` field.
       - **Count of Events** - set as "count" under "Metrics" to quantify the failed logon attempts.

5. **Save and Return**  
   - Click "Save and return" to add the configured visualization to the dashboard.

---

The completed table will display:
- The disabled user account linked to the failed logon.
- The machine reporting the attempt.
- The count of failed logon attempts over the specified timeframe or dataset.
