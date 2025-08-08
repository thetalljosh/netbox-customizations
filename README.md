Of course. Based on the powerful and well-structured script you've finalized, here is a comprehensive `README.md` file suitable for a GitHub repository.

-----

# NetBox SD-WAN and CDP Discovery Script

This PowerShell script provides a robust, multi-layered approach to populating a NetBox instance. It begins by ingesting all edge devices from a Cisco SD-WAN (vManage) environment and then recursively discovers and maps their connected neighbors via CDP.

## Overview

The primary goal of this script is to automate the creation and maintenance of device records in NetBox, ensuring they reflect the reality of your SD-WAN and campus network. It acts as a bridge between your vManage controller and your NetBox source of truth.

### Key Features

  - **SD-WAN Integration:** Connects directly to the vManage API to pull a complete list of cEdge routers.
  - **Recursive CDP Discovery:** Uses the NetBox NAPALM plugin to perform a multi-level discovery of CDP neighbors, mapping out devices connected to your SD-WAN edges.
  - **Comprehensive Object Syncing:** Creates and updates a wide range of NetBox objects, including:
      - Devices
      - Interfaces & IP Addresses
      - Sites, Roles, & Device Types
      - Primary IP assignments
  - **Dynamic Dependency Creation:** If a Site, Role, or Device Type doesn't exist in NetBox, the script creates it on-the-fly.
  - **ARP Table Ingestion:** Pulls ARP tables from SD-WAN routers to discover and log even more IP addresses in your environment.
  - **Intelligent Role Assignment:** Differentiates between Switches and Access Points based on the device platform string.
  - **Data Integrity Protection:** Includes logic to prevent a CDP-discovered device from overwriting an existing, authoritative "Router" role.

-----

## How It Works 🗺️

The script follows a logical, multi-stage workflow to build a detailed picture of your network.

1.  **📡 Authenticate:** The script first establishes authenticated sessions with both the Cisco vManage API and the NetBox API.

2.  **📥 Ingest SD-WAN Devices:** It pulls all device information from vManage. For each SD-WAN router, it syncs the following to NetBox:

      - The device object itself (name, model, serial, etc.).
      - All interfaces, their IP addresses, MAC addresses, and status.
      - The device's System IP is designated as its Primary IP in NetBox.

3.  **🔗 Discover Level 1 Neighbors (CDP):** After syncing an SD-WAN router, the script triggers a NAPALM call via the NetBox API to fetch its CDP neighbors. For each neighbor found:

      - It creates/updates the neighbor device in NetBox.
      - It assigns a role of "Switch" or "Access Point" based on the platform name.
      - It creates the neighbor's management interface and IP address.

4.  **➡️ Discover Level 2 Neighbors (Recursive CDP):** This is where the script goes deeper. For each Level 1 neighbor discovered, it triggers *another* NAPALM call to find *its* neighbors.

      - This requires a separate set of NAPALM credentials, as these devices are not part of the SD-WAN fabric.
      - Any new devices found are also created and mapped in NetBox.

5.  **📝 Sync ARP Tables:** As a final step for each SD-WAN router, the script fetches its ARP table and ensures every IP address is present in NetBox, adding a description of where and when it was last seen.

-----

## Prerequisites

Before running this script, ensure you have the following in place:

  - **PowerShell 5.1** or higher.
  - A **NetBox instance** with the **NAPALM plugin** installed and enabled.
  - **Network Connectivity:** The machine running the script must be able to reach the vManage and NetBox API endpoints.
  - **Firewall Rules:** Your NetBox instance must be able to reach your network devices via SSH/Telnet for the NAPALM service to function.

-----

## Configuration

You must edit the script to provide your environment-specific credentials and URLs. All required variables are located in **Step 1**, **Step 2**, and the recursive discovery step.

```powershell
# --- Step 1: Authenticate to SD-WAN and get JSESSIONID ---
$baseURI = "https://vmanage-instance.sdwan.cisco.com/dataservice"
$response = Invoke-WebRequest -Method Post `
    -Uri "https://vmanage-instance.sdwan.cisco.com/j_security_check" `
    -Headers @{ "Content-Type" = "application/x-www-form-urlencoded" } `
    # Enter your vManage username and password here
    -Body "j_username=SECRET&j_password=SECRET" `
    -SkipCertificateCheck

# --- Step 2: Configure NetBox API Access ---
$netboxbaseurl = "https://SECRET.net/api"
$netboxtoken = "SECRET" # Your NetBox API Token

# --- Inside the main loop, for the recursive neighbor discovery ---
# This is required for NetBox to connect to your non-SDWAN devices
$napalmHeaders = $headers.Clone()
$napalmHeaders.Add("X-NAPALM-Username", "SECRET")
$napalmHeaders.Add("X-NAPALM-Password", "SECRET!")
```

-----

## Usage

Simply execute the script from a PowerShell terminal.

```powershell
.\Sync-NetBoxFromSDWAN.ps1
```

The script includes a `-publicIPonly` switch, which is not fully implemented but can be used as a foundation for future filtering logic.

-----

## License

This project is licensed under the MIT License. See the [LICENSE.md](LICENSE.md) file for details.
