## Key Functionalities for Disk Forensics

- **File Structure Insight**: Provides a navigable view of the file system, allowing quick access to directories and specific files. This feature is critical for locating suspicious files.
- **Hex Viewer**: Enables detailed inspection of files in hexadecimal format, useful when dealing with custom malware or specific exploits.
- **Web Artifacts Analysis**: Allows analysis of user web data, such as browsing history and cached files, which is essential for tracking activities leading up to an incident.
- **Email Carving**: Extracts and displays email data from disk images, often valuable when investigating internal threats or communication-based attacks.
- **Image Viewer**: Facilitates viewing images stored on the system, potentially useful for policy checks or identifying illegal content.
- **Metadata Analysis**: Provides insights into file attributes like creation dates, modification times, and hashes. These details help establish a timeline and correlate with other findings, such as malware activity.

## Autopsy: A Forensic Tool Overview

**Autopsy** is an open-source digital forensics tool that leverages the Sleuth Kit framework. It provides a user-friendly interface with extensive features found in commercial tools, such as:

1. **Data Source Navigation**: Explore files and directories directly within the disk image.
2. **Web Artifact Examination**: Extracts web browsing artifacts like history, bookmarks, and cached files.
3. **Attached Device Analysis**: Identifies and examines external devices connected to the system.
4. **Deleted File Recovery**: Recovers deleted files by scanning the disk sectors for data remnants.
5. **Keyword Searches**: Performs in-depth searches across disk content for specific keywords.
6. **Keyword Lists**: Allows targeted searching using pre-defined lists of keywords (e.g., names, IPs, indicators of compromise).
7. **Timeline Analysis**: Maps out events chronologically, aiding in the construction of an accurate timeline for investigation.

## Practical Use of Autopsy in Forensic Analysis

Once a disk image is loaded in Autopsy, the forensic artifacts are organized in the sidebar, enabling efficient access to:

- **Data Sources**: A view of all files and directories.
- **Web Artifacts**: A focused view of internet history and related data.
- **Device Information**: Details on any attached external devices.
- **Deleted Files**: Recovered files and fragments that were marked for deletion.
- **Keyword & List Searches**: In-depth searching capabilities.
- **Timeline Analysis**: An organized, chronological display of system events, crucial for understanding the sequence of actions leading up to an incident.

https://academy.hackthebox.com/module/237/section/2611