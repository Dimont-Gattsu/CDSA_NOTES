## Splunk Applications Overview
Splunk applications, or apps, are packages that extend the capabilities of Splunk Enterprise or Splunk Cloud, enabling users to manage specific types of operational data. Each app is tailored to handle data from specific technologies or use cases, acting as a pre-built knowledge package for that data. Features provided by Splunk apps include:
- Custom data inputs
- Custom visualizations
- Dashboards, alerts, reports, and more

## Installing and Using the Sysmon App for Splunk

The **Sysmon App for Splunk** by Mike Haag helps enhance security monitoring capabilities. Here’s how to install and configure it:

1. **Sign Up on Splunkbase**
   - Create a free account on Splunkbase.

2. **Download the App**
   - Log in to Splunkbase and locate the Sysmon App for Splunk.

3. **Add the App to the Search Head**
   - Navigate to the Sysmon App page, download the application, and install it on your Splunk Search Head.

4. **Configure the Application**
   - Adjust the app’s macros to load events accurately.

5. **Access the Sysmon App**
   - Go to the "Apps" menu on the Splunk home page, select the Sysmon App, and open the **File Activity** tab.

6. **Set the Time Range**
   - Set the time picker to **All time** and click **Submit**.

## Troubleshooting - “Top Systems” Section Not Displaying Results

- **Problem**: No results in the “Top Systems” section.
- **Solution**:
  1. Click on **Edit** in the upper right corner.
  2. Modify the search to replace `Computer` with `ComputerName` (Sysmon Event ID 11 events use `ComputerName` instead of `Computer`).
  3. Click **Apply** to update and display results.

After these adjustments, results should populate successfully in the "Top Systems" section.
