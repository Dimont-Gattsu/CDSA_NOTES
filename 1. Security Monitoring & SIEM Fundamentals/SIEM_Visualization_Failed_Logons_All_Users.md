## Objective
Create a dashboard and visualization to monitor failed logon attempts for all users.

## Steps

1. **Navigate to the Target System**
   - Access the SIEM tool via `http://[Target IP]:5601`.
   - Go to "Dashboard" from the side navigation.

2. **Delete Existing Dashboard**
   - Remove the "SOC-Alerts" dashboard if present.

3. **Create New Dashboard**
   - Click "Create new dashboard" to start from scratch.

4. **Set Up the Visualization**
   - **Set Date Range**: Use the time picker to select "last 15 years" as the date range, then apply it.
   - **Filter Configuration**  
     - Use Event ID `4625` to filter failed logon attempts.
   - **Index Pattern**  
     - Set `windows*` as the index pattern to use Windows-related logs.
   - **Search Bar Check**  
     - Confirm `user.name.keyword` is in the dataset for accurate aggregation.
   - **Select Visualization Type**  
     - Choose the "Table" option for the display.

5. **Configure Table Settings**
   - **Rows Settings**  
     - Set up rows to display:
       - **Username** - account attempting logon.
       - **Machine** - reporting host machine (`host.hostname.keyword`).
       - **Count of Events** - metric to show number of attempts.
   - **Metrics**  
     - Select "count" to populate the table based on the dataset.

6. **Save the Visualization**
   - Click "Save and return" to add it to the dashboard.

## Refining the Visualization

1. **Edit the Visualization**
   - Access the previously created visualization and select "Edit lens".
   - **Column Names**  
     - Update for clarity as per SOC Manager's suggestion.
   - **Add Logon Type**  
     - Include `winlog.logon.type.keyword` field for detailed logon types.
   - **Sort Results**  
     - Sort the data within the visualization for better readability.
   - **Exclude Specific Usernames**  
     - Filter out usernames like `DESKTOP-DPOESND`, `WIN-OK9BH1BCKSD`, and `WIN-RMMGJA7T9TC`.
   - **Exclude Computer Accounts**  
     - Use a KQL query to exclude computers: `NOT user.name: *$ AND winlog.channel.keyword: Security`.

2. **Save Refinements**
   - Finalize and save the visualization with a suitable title.

---

The completed table will now display:
- Usernames, excluding specified computer accounts.
- Machines where failed attempts occurred.
- The count of failed logon attempts over the defined timeframe.

