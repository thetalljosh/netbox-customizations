param(
    [switch]$publicIPonly
)

# --- Step 1: Authenticate to SD-WAN and get JSESSIONID ---
$baseURI = "https://VMANAGEINSTANCEID.sdwan.cisco.com/dataservice"
$response = Invoke-WebRequest -Method Post `
    -Uri "https://VMANAGEINSTANCEID.sdwan.cisco.com/j_security_check" `
    -Headers @{ "Content-Type" = "application/x-www-form-urlencoded" } `
    -Body "j_username=FAKEUSER&j_password=FAKEPASSWORD" `
    -SkipCertificateCheck

$jsessionid = if ($response.RawContent -match "JSESSIONID=([^;]+)") { $matches[1] } else { throw "Failed to get JSESSIONID." }

# --- Step 2: Configure NetBox API Access ---
$netboxbaseurl = "https://NETBOXURI/api"
$netboxtoken = "NETBOXAPITOKEN"
$headers = @{
    "accept"        = "application/json"
    "Authorization" = "Token $netboxtoken"
    "Content-Type"  = "application/json"
}
# Get the CSRF token from the vManage server
$tokenResponse = Invoke-WebRequest -Method Get `
    -Uri "$baseuri/client/token" `
    -Headers @{ "Cookie" = "JSESSIONID=$jsessionid" } `
    -SkipCertificateCheck

$token = $tokenResponse.Content

# Create a new header object for vManage requests that includes the token
$vManageHeaders = @{
    "Cookie"       = "JSESSIONID=$jsessionid"
    "X-XSRF-TOKEN" = $token
}
# --- Step 2: Configure NetBox API Access ---
$netboxbaseurl = "https://NETBOXADDRESS/api"
$netboxtoken = "NETBOXTOKEN"
$headers = @{
    "accept"        = "application/json"
    "Authorization" = "Token $netboxtoken"
    "Content-Type"  = "application/json"
}

# --- Step 3: Fetch all devices from SD-WAN ---
$devicesResponse = Invoke-WebRequest -Method Get -Uri "$baseuri/device" -Headers @{ "Cookie" = "JSESSIONID=$jsessionid" } -SkipCertificateCheck
$deviceList = ($devicesResponse.Content | ConvertFrom-Json).data

# --- Step 4: Pre-build NetBox ID Lookup Tables for efficiency ---
Write-Host "Building NetBox ID lookup tables..."
$deviceTypeIdMap = @{}
($deviceList | Select-Object -ExpandProperty 'device-model' -Unique) | ForEach-Object {
    $result = (Invoke-WebRequest -Uri "$netboxbaseurl/dcim/device-types/?model=$_" -Headers $headers -SkipCertificateCheck).Content | ConvertFrom-Json
    if ($result.count -gt 0) { $deviceTypeIdMap[$_] = $result.results[0].id }
}

$roleIdMap = @{}
$roleName = "Router" # Assuming all devices are routers
$roleResult = (Invoke-WebRequest -Uri "$netboxbaseurl/dcim/device-roles/?name=$roleName" -Headers $headers -SkipCertificateCheck).Content | ConvertFrom-Json
if ($roleResult.count -gt 0) { $roleIdMap[$roleName] = $roleResult.results[0].id }

$siteIdMap = @{}
($deviceList | ForEach-Object { $_.'host-name'.Split("-")[0] } | Select-Object -Unique) | ForEach-Object {
    $result = (Invoke-WebRequest -Uri "$netboxbaseurl/dcim/sites/?name=$_" -Headers $headers -SkipCertificateCheck).Content | ConvertFrom-Json
    if ($result.count -gt 0) { $siteIdMap[$_] = $result.results[0].id }
}
Write-Host "Lookup tables built."

# --- Step 5: Process Each Device and Sync to NetBox ---
foreach ($device in $deviceList) {
    $hostname = $device.'host-name'
    $systemIp = $device.'system-ip'
    Write-Host "`n--- Processing Device: $hostname ($systemIp) ---"

    # 5.1: Sync Device Object
    $deviceCheck = (Invoke-WebRequest -Uri "$netboxbaseurl/dcim/devices/?name=$hostname" -Headers $headers -SkipCertificateCheck).Content | ConvertFrom-Json
    $netboxDeviceId = $null

    $devicePayload = @{
        serial = $device.uuid
        status = "active"
    }

    if ($deviceCheck.count -gt 0) {
        # Device exists, PATCH it
        $netboxDeviceId = $deviceCheck.results[0].id
        Invoke-WebRequest -Method Patch -Uri "$netboxbaseurl/dcim/devices/$netboxDeviceId/" -Headers $headers -Body ($devicePayload | ConvertTo-Json) -SkipCertificateCheck
        Write-Host "Updated existing device: $hostname"
    }
    else {
        # Device does not exist, POST it
        $devicePayload.name = $hostname
        $devicePayload.device_type = $deviceTypeIdMap[$device.'device-model']
        $devicePayload.role = $roleIdMap[$roleName]
        $devicePayload.site = $siteIdMap[$hostname.Split("-")[0]]

        $createResponse = Invoke-WebRequest -Method Post -Uri "$netboxbaseurl/dcim/devices/" -Headers $headers -Body ($devicePayload | ConvertTo-Json) -SkipCertificateCheck
        $netboxDeviceId = ($createResponse.Content | ConvertFrom-Json).id
        Write-Host "Created new device: $hostname"
    }

    if (-not $netboxDeviceId) {
        Write-Warning "Could not get NetBox ID for device $hostname. Skipping its interfaces and IPs."
        continue
    }
    # 5.2: Fetch and Sync Interfaces for the current device
    $interfaceUri = "$baseuri/device/interface?deviceId=$systemIp"
    $interfaceResponse = Invoke-WebRequest -Method Get -Uri $interfaceUri -Headers @{ "Cookie" = "JSESSIONID=$jsessionid" } -SkipCertificateCheck
    $interfaceList = ($interfaceResponse.Content | ConvertFrom-Json).data

    if ($null -ne $interfaceList) {
        foreach ($interface in $interfaceList) {
            # Skip interfaces with no IP unless you want to create them all
            if ($interface.'ip-address' -eq "N/A" -or $interface.'ip-address' -eq "0.0.0.0") { continue }
            
            $interfaceName = $interface.ifname
            $netboxInterfaceId = $null
            $interfaceCheck = (Invoke-WebRequest -Uri "$netboxbaseurl/dcim/interfaces/?device_id=$netboxDeviceId&name=$interfaceName" -Headers $headers -SkipCertificateCheck).Content | ConvertFrom-Json

            # Map SD-WAN status to NetBox boolean
            $isEnabled = $interface.'if-admin-status' -eq 'Up'

            $interfacePayload = @{
                mac_address = $interface.hwaddr
                enabled     = $isEnabled
                description = "VPN: $($interface.'vpn-id'), Port Type: $($interface.'port-type')"
            }

            if ($interfaceCheck.count -gt 0) {
                # Interface exists, PATCH it
                $netboxInterfaceId = $interfaceCheck.results[0].id
                Invoke-WebRequest -Method Patch -Uri "$netboxbaseurl/dcim/interfaces/$netboxInterfaceId/" -Headers $headers -Body ($interfacePayload | ConvertTo-Json) -SkipCertificateCheck
            }
            else {
                # Interface does not exist, POST it
                $interfacePayload.name = $interfaceName
                $interfacePayload.device = $netboxDeviceId
                $interfacePayload.type = "other" # Or add more complex mapping logic here

                $createResponse = Invoke-WebRequest -Method Post -Uri "$netboxbaseurl/dcim/interfaces/" -Headers $headers -Body ($interfacePayload | ConvertTo-Json) -SkipCertificateCheck
                $netboxInterfaceId = ($createResponse.Content | ConvertFrom-Json).id
            }
            Write-Host "Synced interface: $interfaceName"

            # 5.3 Sync IP Address for the Interface
            $ipAddress = "$($interface.'ip-address')"
            $ipCheck = (Invoke-WebRequest -Uri "$netboxbaseurl/ipam/ip-addresses/?address=$ipAddress" -Headers $headers -SkipCertificateCheck).Content | ConvertFrom-Json
            
            $ipPayload = @{
                assigned_object_type = "dcim.interface"
                assigned_object_id   = $netboxInterfaceId
            }

            if ($ipCheck.count -gt 0) {
                # IP exists, PATCH it to ensure it's assigned to the correct interface
                $netboxIpId = $ipCheck.results[0].id
                # Only patch if the assignment is different
                if ($ipCheck.results[0].assigned_object.id -ne $netboxInterfaceId) {
                    Invoke-WebRequest -Method Patch -Uri "$netboxbaseurl/ipam/ip-addresses/$netboxIpId/" -Headers $headers -Body ($ipPayload | ConvertTo-Json) -SkipCertificateCheck
                    Write-Host "Updated IP assignment for $($interface.'ip-address')"
                }
            }
            else {
                # IP does not exist, POST it
                $ipPayload.address = $ipAddress
                $ipPayload.status = "active"
                $createIpResp = Invoke-WebRequest -Method Post -Uri "$netboxbaseurl/ipam/ip-addresses/" -Headers $headers -Body ($ipPayload | ConvertTo-Json) -SkipCertificateCheck
                $netboxIpId = ($createIpResp.Content | ConvertFrom-Json).id
                Write-Host "Created IP Address: $($interface.'ip-address')"
            }

            # If this is the Sdwan-system-intf, set as primary IPv4 for the device
            if ($interfaceName -eq "Sdwan-system-intf" -and $netboxIpId) {
                $primaryPayload = @{
                    primary_ip4 = $netboxIpId
                } | ConvertTo-Json
                Invoke-WebRequest -Method Patch -Uri "$netboxbaseurl/dcim/devices/$netboxDeviceId/" -Headers $headers -Body $primaryPayload -SkipCertificateCheck
                Write-Host "Set $ipAddress as primary IPv4 for device $hostname"
            }
        }
    }

    # Hit the netbox API and get lldp neighbors with the napalm plugin and deviceid
    # Fetch LLDP neighbors using the NetBox napalm plugin for this device
    # http://netbox/api/dcim/devices/64/napalm/?method=get_lldp_neighbors
    # plugins/netbox_napalm_plugin/napalmplatformconfig/55/napalm/?method=get_lldp_neighbors
    $napalmUri = "$netboxbaseurl/plugins/netbox_napalm_plugin/napalmplatformconfig/$netboxDeviceId/napalm/?method=get_cdp_neighbors_detail"
    try {
        $lldpResponse = Invoke-WebRequest -Method Get -Uri $napalmUri -Headers $headers -SkipCertificateCheck
        $lldpNeighbors = ($lldpResponse.Content | ConvertFrom-Json).get_cdp_neighbors_detail
        if ($lldpNeighbors) {
            Write-Host "LLDP neighbors for $hostname"
            $lldpNeighbors.PSObject.Properties | ForEach-Object {
                $localInt = $_.Name
                foreach ($neighbor in $_.Value) {
                    Write-Host "  Local Interface: $localInt"
                    foreach ($key in $neighbor.PSObject.Properties.Name) {
                        Write-Host "    $key : $($neighbor.$key)"
                    }
                    # Ensure neighbor model exists in NetBox device-types
                    $neighborModel = $neighbor.remote_system.platform
                    if (![string]::IsNullOrWhiteSpace($neighborModel) -and -not $deviceTypeIdMap.ContainsKey($neighborModel)) {
                        $modelPayload = @{
                            model        = $neighborModel
                            manufacturer = 1 # Cisco
                            slug         = $neighborModel.ToLower() -replace '[^a-z0-9]+', '-'
                        } | ConvertTo-Json
                        $modelResp = Invoke-WebRequest -Method Post -Uri "$netboxbaseurl/dcim/device-types/" -Headers $headers -Body $modelPayload -SkipCertificateCheck
                        $deviceTypeIdMap[$neighborModel] = ($modelResp.Content | ConvertFrom-Json).id
                    }
                  
                    # Ensure device role "Switch" exists
                    if (-not $roleIdMap.ContainsKey("Switch")) {
                        $rolePayload = @{
                            name  = "Switch"
                            slug  = "switch"
                            color = "00ff00"
                        } | ConvertTo-Json
                        $roleResp = Invoke-WebRequest -Method Post -Uri "$netboxbaseurl/dcim/device-roles/" -Headers $headers -Body $rolePayload -SkipCertificateCheck
                        $roleIdMap["Switch"] = ($roleResp.Content | ConvertFrom-Json).id
                    }

                    # Ensure site exists (use the same as the current device)
                    $neighborSite = $hostname.Split("-")[0]
                    if (-not $siteIdMap.ContainsKey($neighborSite)) {
                        $sitePayload = @{
                            name = $neighborSite
                            slug = $neighborSite.ToLower()
                        } | ConvertTo-Json
                        $siteResp = Invoke-WebRequest -Method Post -Uri "$netboxbaseurl/dcim/sites/" -Headers $headers -Body $sitePayload -SkipCertificateCheck
                        $siteIdMap[$neighborSite] = ($siteResp.Content | ConvertFrom-Json).id
                    }

                    # Check if the neighbor device already exists
                    $neighborName = $neighbor.remote_system_name
                    if (![string]::IsNullOrWhiteSpace($neighborName)) {
                        $neighborCheck = (Invoke-WebRequest -Uri "$netboxbaseurl/dcim/devices/?name=$neighborName" -Headers $headers -SkipCertificateCheck).Content | ConvertFrom-Json
                        $neighborDeviceId = $null

                        $neighborPayload = @{
                            serial      = ""
                            status      = "active"
                        }

                        if ($neighborCheck.count -gt 0) {
                            # Device exists, PATCH it
                            $neighborDeviceId = $neighborCheck.results[0].id
                            if ($deviceTypeIdMap.ContainsKey($neighborModel)) { $neighborPayload.device_type = $deviceTypeIdMap[$neighborModel] }
                            if ($roleIdMap.ContainsKey("Switch")) { $neighborPayload.role = $roleIdMap["Switch"] }
                            if ($siteIdMap.ContainsKey($neighborSite)) { $neighborPayload.site = $siteIdMap[$neighborSite] }
                            $neighborPayload.platform = 1 # Assuming Cisco platform
                            $neighborPayload.description = "Discovered as LLDP neighbor of $hostname"
                            if ($neighbor.remote_mac_address) { $neighborPayload.mac_address = $neighbor.remote_mac_address }
                            # Remove null or empty properties
                            $neighborPayload = $neighborPayload.GetEnumerator() | Where-Object { $_.Value -ne $null -and $_.Value -ne "" } | ForEach-Object { @{ ($_.Key) = $_.Value } }
                            $finalPatchPayload = @{}
                            foreach ($item in $neighborPayload) {
                                foreach ($k in $item.Keys) { $finalPatchPayload[$k] = $item[$k] }
                            }
                            Invoke-WebRequest -Method Patch -Uri "$netboxbaseurl/dcim/devices/$neighborDeviceId/" -Headers $headers -Body ($finalPatchPayload | ConvertTo-Json) -SkipCertificateCheck
                            Write-Host "Patched neighbor device: $neighborName"
                        }
                        else {
                            # Device does not exist, POST it
                            $neighborPayload.name = $neighborName
                            $neighborPayload.device_type = $deviceTypeIdMap.ContainsKey($neighborModel) ? $deviceTypeIdMap[$neighborModel] : $null
                            $neighborPayload.role = $roleIdMap["Switch"]
                            $neighborPayload.site = $siteIdMap[$neighborSite]
                            $neighborPayload.platform = 1 # Assuming Cisco platform
                            $neighborPayload.description = "Discovered as LLDP neighbor of $hostname"
                            if ($neighbor.remote_mac_address) { $neighborPayload.mac_address = $neighbor.remote_mac_address }
                            # Remove null or empty properties
                            $neighborPayload = $neighborPayload.GetEnumerator() | Where-Object { $_.Value -ne $null -and $_.Value -ne "" } | ForEach-Object { @{ ($_.Key) = $_.Value } }
                            $finalPayload = @{}
                            foreach ($item in $neighborPayload) {
                                foreach ($k in $item.Keys) { $finalPayload[$k] = $item[$k] }
                            }
                            $createResponse = Invoke-WebRequest -Method Post -Uri "$netboxbaseurl/dcim/devices/" -Headers $headers -Body ($finalPayload | ConvertTo-Json) -SkipCertificateCheck
                            $neighborDeviceId = ($createResponse.Content | ConvertFrom-Json).id
                            Write-Host "Created neighbor device: $neighborName"
                        }

                        if (-not $neighborDeviceId) {
                            Write-Warning "Could not get NetBox ID for neighbor device $neighborName. Skipping its interfaces and IPs."
                            continue
                        }

                        # Ensure neighbor interface exists in NetBox interfaces
                        $neighborInterfaceName = $neighbor.remote_port
                        $neighborInterfaceCheck = (Invoke-WebRequest -Uri "$netboxbaseurl/dcim/interfaces/?device_id=$neighborDeviceId&name=$neighborInterfaceName" -Headers $headers -SkipCertificateCheck).Content | ConvertFrom-Json
                        $neighborInterfaceId = $null
                        if ($neighborInterfaceCheck.count -gt 0) {
                            $neighborInterfaceId = $neighborInterfaceCheck.results[0].id
                        }
                        else {
                            $neighborInterfacePayload = @{
                                name        = $neighborInterfaceName
                                device      = $neighborDeviceId
                                type        = "other" # Assuming other type, adjust as needed
                                mac_address = $neighbor.remote_mac_address
                                description = "CDP neighbor interface"
                            }
                            $createIntfResp = Invoke-WebRequest -Method Post -Uri "$netboxbaseurl/dcim/interfaces/" -Headers $headers -Body ($neighborInterfacePayload | ConvertTo-Json) -SkipCertificateCheck
                            $neighborInterfaceId = ($createIntfResp.Content | ConvertFrom-Json).id
                            Write-Host "Created CDP neighbor interface: $neighborInterfaceName"
                        }

                        # Ensure neighbor IP exists in NetBox ip-addresses and assign to interface
                        $neighborIp = $neighbor.remote_ip_address
                        if (![string]::IsNullOrWhiteSpace($neighborIp)) {
                            $neighborIpCheck = (Invoke-WebRequest -Uri "$netboxbaseurl/ipam/ip-addresses/?address=$neighborIp" -Headers $headers -SkipCertificateCheck).Content | ConvertFrom-Json
                            $ipPayload = @{
                                address              = $neighborIp
                                status               = "active"
                                description          = "Discovered as LLDP neighbor of $hostname"
                                assigned_object_type = "dcim.interface"
                                assigned_object_id   = $neighborInterfaceId
                            }
                            $netboxNeighborIpId = $null
                            if ($neighborIpCheck.count -eq 0) {
                                $createIpResp = Invoke-WebRequest -Method Post -Uri "$netboxbaseurl/ipam/ip-addresses/" -Headers $headers -Body ($ipPayload | ConvertTo-Json) -SkipCertificateCheck
                                $netboxNeighborIpId = ($createIpResp.Content | ConvertFrom-Json).id
                                Write-Host "Created and assigned neighbor IP: $neighborIp"
                            } else {
                                $netboxNeighborIpId = $neighborIpCheck.results[0].id
                                # Patch if not assigned to this interface
                                if ($neighborIpCheck.results[0].assigned_object.id -ne $neighborInterfaceId) {
                                    $patchPayload = @{
                                        assigned_object_type = "dcim.interface"
                                        assigned_object_id   = $neighborInterfaceId
                                    } | ConvertTo-Json
                                    Invoke-WebRequest -Method Patch -Uri "$netboxbaseurl/ipam/ip-addresses/$netboxNeighborIpId/" -Headers $headers -Body $patchPayload -SkipCertificateCheck
                                    Write-Host "Updated neighbor IP assignment for $neighborIp"
                                }
                            }
                            # Set as primary IPv4 for the neighbor device if not already set
                            if ($netboxNeighborIpId) {
                                $neighborDeviceCheck = (Invoke-WebRequest -Uri "$netboxbaseurl/dcim/devices/$neighborDeviceId/" -Headers $headers -SkipCertificateCheck).Content | ConvertFrom-Json
                                if (-not $neighborDeviceCheck.primary_ip4 -or $neighborDeviceCheck.primary_ip4.id -ne $netboxNeighborIpId) {
                                    $primaryPayload = @{
                                        primary_ip4 = $netboxNeighborIpId
                                    } | ConvertTo-Json
                                    Invoke-WebRequest -Method Patch -Uri "$netboxbaseurl/dcim/devices/$neighborDeviceId/" -Headers $headers -Body $primaryPayload -SkipCertificateCheck
                                    Write-Host "Set $neighborIp as primary IPv4 for neighbor device $neighborName"
                                }
                            }
                        }
                    }
                }
            }
        }
        else {
            Write-Host "No LLDP neighbors found for $hostname."
        }
    }
    catch {
        Write-Warning "Failed to fetch LLDP neighbors for $hostname $_"
    }

    # 5.4 Fetch and Sync ARP entries for the current device
    $arpUri = "$baseuri/device/arp?deviceId=$systemIp"
    $arpResponse = Invoke-WebRequest -Method Get -Uri $arpUri -Headers @{ "Cookie" = "JSESSIONID=$jsessionid" } -SkipCertificateCheck
    $arpTable = ($arpResponse.content | ConvertFrom-Json).data

    if ($null -ne $arpTable) {
        foreach ($arpEntry in $arpTable) {
            if ($null -ne $arpEntry.interface -and $arpEntry.hardware -notlike "00:00:00:00:00:00" -and $arpEntry.address -ne "0.0.0.0") {
                $arpIp = "$($arpEntry.address)"
                $arpCheck = (Invoke-WebRequest -Uri "$netboxbaseurl/ipam/ip-addresses/?address=$arpIp" -Headers $headers -SkipCertificateCheck).Content | ConvertFrom-Json
                
                $arpDescription = "Discovered via ARP on $hostname (Interface: $($arpEntry.interface), MAC: $($arpEntry.hardware)) at $(Get-Date)"

                if ($arpCheck.count -gt 0) {
                    # ARP IP exists, just update its description with the latest sighting
                    $netboxArpIpId = $arpCheck.results[0].id
                    $arpPayload = @{ description = $arpDescription } | ConvertTo-Json
                    Invoke-WebRequest -Method Patch -Uri "$netboxbaseurl/ipam/ip-addresses/$netboxArpIpId/" -Headers $headers -Body $arpPayload -SkipCertificateCheck
                }
                else {
                    # ARP IP does not exist, create it without an interface assignment
                    $arpPayload = @{
                        address     = $arpIp
                        status      = "active"
                        description = $arpDescription
                    } | ConvertTo-Json
                    Invoke-WebRequest -Method Post -Uri "$netboxbaseurl/ipam/ip-addresses/" -Headers $headers -Body $arpPayload -SkipCertificateCheck
                }
                Write-Host "Synced ARP entry for $($arpEntry.address)"
            }
        }
    }
}

Write-Host "`n--- Synchronization Complete ---"
