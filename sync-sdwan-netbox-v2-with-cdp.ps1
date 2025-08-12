param(
    [switch]$publicIPonly
)

#==============================================================================
#   Reusable Function to Sync a Device and its Dependencies to NetBox
#==============================================================================
function Sync-DeviceToNetBox {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$DeviceInfo,

        # Pass script-level context as parameters for better encapsulation
        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,
        [Parameter(Mandatory = $true)]
        [string]$NetboxBaseUrl,
        [Parameter(Mandatory = $true)]
        [hashtable]$SiteIdMap,
        [Parameter(Mandatory = $true)]
        [hashtable]$RoleIdMap,
        [Parameter(Mandatory = $true)]
        [hashtable]$DeviceTypeIdMap,
        [Parameter(Mandatory = $false)]
        [bool]$discoveredByCDP = $false
    )

    $hostname = $DeviceInfo.Name
    if ([string]::IsNullOrWhiteSpace($hostname)) {
        Write-Warning "Device name is missing. Skipping this entry."
        return $null
    }
    Write-Host "`n--- Syncing Device: $hostname ---"

    # 1. Ensure Dependencies Exist (Site, Role, Model/DeviceType)
    # Site
    $siteId = $null
    if ($DeviceInfo.SiteName) {
        if (-not $SiteIdMap.ContainsKey($DeviceInfo.SiteName)) {
            Write-Host "Site '$($DeviceInfo.SiteName)' not found in cache, creating..."
            $sitePayload = @{ name = $DeviceInfo.SiteName; slug = $DeviceInfo.SiteName.ToLower() -replace '[^a-z0-9\-_]+', '-' } | ConvertTo-Json
            try {
                $siteResp = Invoke-WebRequest -Method Post -Uri "$NetboxBaseUrl/dcim/sites/" -Headers $Headers -Body $sitePayload -SkipCertificateCheck -ErrorAction Stop
                $SiteIdMap[$DeviceInfo.SiteName] = ($siteResp.Content | ConvertFrom-Json).id
            }
            catch { Write-Warning "Failed to create site '$($DeviceInfo.SiteName)': $_" }
        }
        $siteId = $SiteIdMap[$DeviceInfo.SiteName]
    }

    # Role
    $roleId = $null
    if ($DeviceInfo.RoleName) {
        if (-not $RoleIdMap.ContainsKey($DeviceInfo.RoleName)) {
            Write-Host "Role '$($DeviceInfo.RoleName)' not found in cache, creating..."
            $rolePayload = @{ name = $DeviceInfo.RoleName; slug = $DeviceInfo.RoleName.ToLower() -replace '[^a-z0-9\-_]+', '-'; color = "3498db" } | ConvertTo-Json
            try {
                $roleResp = Invoke-WebRequest -Method Post -Uri "$NetboxBaseUrl/dcim/device-roles/" -Headers $Headers -Body $rolePayload -SkipCertificateCheck -ErrorAction Stop
                $RoleIdMap[$DeviceInfo.RoleName] = ($roleResp.Content | ConvertFrom-Json).id
            }
            catch { Write-Warning "Failed to create role '$($DeviceInfo.RoleName)': $_" }
        }
        $roleId = $RoleIdMap[$DeviceInfo.RoleName]
    }

    # Device Type (Model)
    $deviceTypeId = $null
    if ($DeviceInfo.DeviceModel) {
        if (-not $DeviceTypeIdMap.ContainsKey($DeviceInfo.DeviceModel)) {
            $modelCheck = (Invoke-WebRequest -Uri "$NetboxBaseUrl/dcim/device-types/?model=$($DeviceInfo.DeviceModel)" -Headers $Headers -SkipCertificateCheck).Content | ConvertFrom-Json
            if ($modelCheck.count -gt 0) {
                $DeviceTypeIdMap[$DeviceInfo.DeviceModel] = $modelCheck.results[0].id
            }
            else {
                Write-Host "Device Type '$($DeviceInfo.DeviceModel)' not found, creating..."
                $modelPayload = @{ model = $DeviceInfo.DeviceModel; manufacturer = 1; slug = $DeviceInfo.DeviceModel.ToLower() -replace '[^a-z0-9\-_]+', '-' } | ConvertTo-Json
                try {
                    $modelResp = Invoke-WebRequest -Method Post -Uri "$NetboxBaseUrl/dcim/device-types/" -Headers $Headers -Body $modelPayload -SkipCertificateCheck -ErrorAction Stop
                    $DeviceTypeIdMap[$DeviceInfo.DeviceModel] = ($modelResp.Content | ConvertFrom-Json).id
                }
                catch { Write-Warning "Failed to create device type '$($DeviceInfo.DeviceModel)': $_" }
            }
        }
        $deviceTypeId = $DeviceTypeIdMap[$DeviceInfo.DeviceModel]
    }

    # 2. Sync Device Object
    $deviceCheck = (Invoke-WebRequest -Uri "$NetboxBaseUrl/dcim/devices/?name=$hostname" -Headers $Headers -SkipCertificateCheck).Content | ConvertFrom-Json
    $netboxDeviceId = $null
    if ( $devicecheck.results[0].role.name -eq "Router" -and $discoveredByCDP) {
        Write-Host "Device $hostname is a Router and was discovered by CDP. Skipping update to avoid overwriting role."
        return $null
    }

    $devicePayload = @{}
    # Dynamically build payload from provided info
    if ($DeviceInfo.SerialNumber) { $devicePayload.serial = $DeviceInfo.SerialNumber }
    if ($DeviceInfo.Description) { $devicePayload.description = $DeviceInfo.Description }

    if ($deviceCheck.count -gt 0) {
       
        $netboxDeviceId = $deviceCheck.results[0].id
        Invoke-WebRequest -Method Patch -Uri "$NetboxBaseUrl/dcim/devices/$netboxDeviceId/" -Headers $Headers -Body ($devicePayload | ConvertTo-Json) -SkipCertificateCheck
        Write-Host "Updated existing device: $hostname (ID: $netboxDeviceId)"
    }
    else {
        $devicePayload.name = $hostname
        if ($deviceTypeId) { $devicePayload.device_type = $deviceTypeId }
        if ($roleId) { $devicePayload.role = $roleId }
        if ($siteId) { $devicePayload.site = $siteId }
        
        try {
            $createResponse = Invoke-WebRequest -Method Post -Uri "$NetboxBaseUrl/dcim/devices/" -Headers $Headers -Body ($devicePayload | ConvertTo-Json) -SkipCertificateCheck -ErrorAction Stop
            $netboxDeviceId = ($createResponse.Content | ConvertFrom-Json).id
            Write-Host "Created new device: $hostname (ID: $netboxDeviceId)"
        }
        catch {
            Write-Warning "Failed to create device '$hostname'. $_"
            return $null
        }
    }

    if (-not $netboxDeviceId) { return $null }

    # 3. Sync Interfaces and IPs
    if ($DeviceInfo.Interfaces) {
        foreach ($interface in $DeviceInfo.Interfaces) {
            $interfaceName = $interface.Name
            $ipAddressWithPrefix = $interface.IPAddress
            
            # Skip if interface has no valid IP data
            if ([string]::IsNullOrWhiteSpace($ipAddressWithPrefix) -or $ipAddressWithPrefix -eq "N/A" -or $ipAddressWithPrefix -eq "0.0.0.0") { continue }

            $netboxInterfaceId = $null
            $interfaceCheck = (Invoke-WebRequest -Uri "$NetboxBaseUrl/dcim/interfaces/?device_id=$netboxDeviceId&name=$interfaceName" -Headers $Headers -SkipCertificateCheck).Content | ConvertFrom-Json

            $interfacePayload = @{}
            if ($interface.ContainsKey('MACAddress')) { $interfacePayload.mac_address = $interface.MACAddress }
            if ($interface.ContainsKey('Enabled')) { $interfacePayload.enabled = $interface.Enabled }
            if ($interface.ContainsKey('Description')) { $interfacePayload.description = $interface.Description }

            if ($interfaceCheck.count -gt 0) {
                $netboxInterfaceId = $interfaceCheck.results[0].id
                Invoke-WebRequest -Method Patch -Uri "$NetboxBaseUrl/dcim/interfaces/$netboxInterfaceId/" -Headers $Headers -Body ($interfacePayload | ConvertTo-Json) -SkipCertificateCheck
            }
            else {
                $interfacePayload.name = $interfaceName
                $interfacePayload.device = $netboxDeviceId
                $interfacePayload.type = $interface.Type
                $createResponse = Invoke-WebRequest -Method Post -Uri "$NetboxBaseUrl/dcim/interfaces/" -Headers $Headers -Body ($interfacePayload | ConvertTo-Json) -SkipCertificateCheck
                $netboxInterfaceId = ($createResponse.Content | ConvertFrom-Json).id
            }
            Write-Host "  - Synced interface: $interfaceName"

            # Sync IP Address
            $ipAddressOnly = $ipAddressWithPrefix.Split('/')[0]
            $ipCheck = (Invoke-WebRequest -Uri "$NetboxBaseUrl/ipam/ip-addresses/?address=$ipAddressOnly" -Headers $Headers -SkipCertificateCheck).Content | ConvertFrom-Json
            $netboxIpId = $null
            $ipPayload = @{ assigned_object_type = "dcim.interface"; assigned_object_id = $netboxInterfaceId }

            if ($ipCheck.count -gt 0) {
                $netboxIpId = $ipCheck.results[0].id
                if ($ipCheck.results[0].assigned_object.id -ne $netboxInterfaceId) {
                    Invoke-WebRequest -Method Patch -Uri "$NetboxBaseUrl/ipam/ip-addresses/$netboxIpId/" -Headers $Headers -Body ($ipPayload | ConvertTo-Json) -SkipCertificateCheck
                    Write-Host "    - Updated IP assignment for $ipAddressWithPrefix"
                }
            }
            else {
                $ipPayload.address = $ipAddressWithPrefix
                $ipPayload.status = "active"
                $createIpResp = Invoke-WebRequest -Method Post -Uri "$NetboxBaseUrl/ipam/ip-addresses/" -Headers $Headers -Body ($ipPayload | ConvertTo-Json) -SkipCertificateCheck
                $netboxIpId = ($createIpResp.Content | ConvertFrom-Json).id
                Write-Host "    - Created IP Address: $ipAddressWithPrefix"
            }

            # Set Primary IP if applicable
            if ($netboxIpId -and $DeviceInfo.PrimaryIPInterfaceName -and ($interfaceName -eq $DeviceInfo.PrimaryIPInterfaceName)) {
                $primaryPayload = @{ primary_ip4 = $netboxIpId } | ConvertTo-Json
                Invoke-WebRequest -Method Patch -Uri "$NetboxBaseUrl/dcim/devices/$netboxDeviceId/" -Headers $Headers -Body $primaryPayload -SkipCertificateCheck
                Write-Host "  - Set $ipAddressWithPrefix as primary IPv4 for device $hostname"
            }
        }
    }
    return $netboxDeviceId
}

function Connect-NetBoxInterfaces {
    param(
        [Parameter(Mandatory = $true)] $InterfaceA_ID,
        [Parameter(Mandatory = $true)] $InterfaceB_ID,
        [Parameter(Mandatory = $true)] $Headers,
        [Parameter(Mandatory = $true)] $NetboxBaseUrl
    )

    # Check if interface A is already connected to prevent errors
    $checkA = (Invoke-WebRequest -Uri "$NetboxBaseUrl/dcim/interfaces/$InterfaceA_ID/" -Headers $Headers -SkipCertificateCheck).Content | ConvertFrom-Json
    if ($checkA.cable) {
        Write-Host "--> Interface ID $InterfaceA_ID is already connected. Skipping cable creation."
        return
    }

    # Check if interface B is already connected
    $checkB = (Invoke-WebRequest -Uri "$NetboxBaseUrl/dcim/interfaces/$InterfaceB_ID/" -Headers $Headers -SkipCertificateCheck).Content | ConvertFrom-Json
    if ($checkB.cable) {
        Write-Host "--> Interface ID $InterfaceB_ID is already connected. Skipping cable creation."
        return
    }

    # Construct the payload according to the required nested schema.
    $cablePayload = @{
        type = "cat6"
        a_terminations = @(
            @{
                object_type = "dcim.interface"
                object_id   = $InterfaceA_ID
            }
        )
        b_terminations = @(
            @{
                object_type = "dcim.interface"
                object_id   = $InterfaceB_ID
            }
        )
        status = "connected"
    }

$cablePayload = $cablePayload | ConvertTo-Json -Depth 5

    try {
        Invoke-WebRequest -Method Post -Uri "$NetboxBaseUrl/dcim/cables/" -Headers $Headers -Body $cablePayload -SkipCertificateCheck -ErrorAction Stop
        Write-Host "--> Successfully created cable between interface $InterfaceA_ID and $InterfaceB_ID."
    }
    catch {
        Write-Warning "--> Failed to create cable between interface $InterfaceA_ID and $InterfaceB_ID : $_"
    }
}


# --- Step 1: Authenticate to SD-WAN and get JSESSIONID ---
$baseURI = "https://vmanage-CONTOSO.sdwan.cisco.com/dataservice"
$response = Invoke-WebRequest -Method Post `
    -Uri "https://vmanage-CONTOSO.sdwan.cisco.com/j_security_check" `
    -Headers @{ "Content-Type" = "application/x-www-form-urlencoded" } `
    -Body "j_username=CONTOSO&j_password=CONTOSO" `
    -SkipCertificateCheck
$jsessionid = if ($response.RawContent -match "JSESSIONID=([^;]+)") { $matches[1] } else { throw "Failed to get JSESSIONID." }
$tokenResponse = Invoke-WebRequest -Method Get `
    -Uri "$baseuri/client/token" `
    -Headers @{ "Cookie" = "JSESSIONID=$jsessionid" } `
    -SkipCertificateCheck
$token = $tokenResponse.Content
$vManageHeaders = @{
    "Cookie"       = "JSESSIONID=$jsessionid"
    "X-XSRF-TOKEN" = $token
}

# --- Step 2: Configure NetBox API Access ---
$netboxbaseurl = "https://CONTOSO.net/api"
$netboxtoken = "CONTOSO"
$headers = @{
    "accept"        = "application/json"
    "Authorization" = "Token $netboxtoken"
    "Content-Type"  = "application/json"
}

# --- Step 3: Fetch all devices from SD-WAN ---
$devicesResponse = Invoke-WebRequest -Method Get -Uri "$baseuri/device" -Headers @{ "Cookie" = "JSESSIONID=$jsessionid" } -SkipCertificateCheck
$deviceList = ($devicesResponse.Content | ConvertFrom-Json).data

# --- Step 4: Pre-build NetBox ID Lookup Tables for efficiency ---
# Using $ scope to make these accessible and modifiable within the function
Write-Host "Building NetBox ID lookup tables..."
$deviceTypeIdMap = @{}
($deviceList | Select-Object -ExpandProperty 'device-model' -Unique) | ForEach-Object {
    $result = (Invoke-WebRequest -Uri "$netboxbaseurl/dcim/device-types/?model=$_" -Headers $headers -SkipCertificateCheck).Content | ConvertFrom-Json
    if ($result.count -gt 0) { $deviceTypeIdMap[$_] = $result.results[0].id }
}

$roleIdMap = @{}
"Router", "Switch" | ForEach-Object {
    $roleName = $_
    $roleResult = (Invoke-WebRequest -Uri "$netboxbaseurl/dcim/device-roles/?name=$roleName" -Headers $headers -SkipCertificateCheck).Content | ConvertFrom-Json
    if ($roleResult.count -gt 0) { $roleIdMap[$roleName] = $roleResult.results[0].id }
}

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
    
    if ($hostname -like "vmanage*" -or $hostname -like "vsmart*" -or $hostname -like "vBond*") {
        Write-Host "Skipping controller: $hostname"
        continue
    }

    # 5.1: Sync SD-WAN Device using the new function
    # Gather interfaces for this device first
    $interfaceUri = "$baseuri/device/interface?deviceId=$systemIp"
    $interfaceResponse = Invoke-WebRequest -Method Get -Uri $interfaceUri -Headers @{ "Cookie" = "JSESSIONID=$jsessionid" } -SkipCertificateCheck
    $interfaceList = ($interfaceResponse.Content | ConvertFrom-Json).data

    $interfacesForNetbox = @()
    if ($null -ne $interfaceList) {
        $interfacesForNetbox = $interfaceList | ForEach-Object {
            @{
                Name        = $_.ifname
                IPAddress   = $_.'ip-address' # Note: Function expects prefix, SD-WAN API may not provide it. Add "/32" or as appropriate.
                MACAddress  = $_.hwaddr
                Enabled     = $_.'if-admin-status' -eq 'Up'
                Description = "VPN: $($_. 'vpn-id'), Port Type: $($_. 'port-type')"
                Type        = "other"
            }
        }
    }

    $deviceInfo = @{
        Name                   = $hostname
        SiteName               = $hostname.Split("-")[0]
        RoleName               = "Router"
        DeviceModel            = $device.'device-model'
        SerialNumber           = $device.uuid
        Status                 = "active"
        Interfaces             = $interfacesForNetbox
        PrimaryIPInterfaceName = "Sdwan-system-intf"
    }

    # Call the reusable function to sync the device
    $netboxDevice = (Sync-DeviceToNetBox -DeviceInfo $deviceInfo -Headers $headers -NetboxBaseUrl $netboxbaseurl -SiteIdMap $siteIdMap -RoleIdMap $roleIdMap -DeviceTypeIdMap $deviceTypeIdMap) | ConvertFrom-Json
    $netboxDeviceId = $netboxDevice[0].id
    if (-not $netboxDeviceId) {
        Write-Warning "Could not get NetBox ID for device $hostname. Skipping neighbor discovery."
        continue
    }

    # 5.2 Discover and Sync CDP Neighbors
    $napalmUri = "$netboxbaseurl/plugins/netbox_napalm_plugin/napalmplatformconfig/$netboxDeviceId/napalm/?method=get_cdp_neighbors_detail"
    try {
        $CDPResponse = Invoke-WebRequest -Method Get -Uri $napalmUri -Headers $headers -SkipCertificateCheck -ErrorAction Stop
        $CDPNeighbors = ($CDPResponse.Content | ConvertFrom-Json).get_cdp_neighbors_detail
        
        if ($CDPNeighbors) {
            Write-Host "Found CDP neighbors for $hostname. Processing..."
            $CDPNeighbors.PSObject.Properties | ForEach-Object {
                foreach ($neighbor in $_.Value) {
                    # Prepare info for the neighbor device
                    if ($neighbor.remote_system.platform -like "*-AP*") { $neighborRole = "Access Point" }
                    else { $neighborRole = "Switch" }
                    $neighborInfo = @{
                        Name                   = $neighbor.remote_system_name
                        SiteName               = $hostname.Split("-")[0] # Assume same site as parent
                        RoleName               = $neighborRole
                        DeviceModel            = $Neighbor.remote_system.platform
                        Status                 = "active"
                        Description            = $neighbor.remote_system.neighbor_description
                        Interfaces             = @(
                            @{
                                Name      = $neighbor.remote_interface
                                IPAddress = $neighbor.remote_ip_address # May need prefix
                                Type      = "other"
                            }
                        )
                        PrimaryIPInterfaceName = $neighbor.remote_interface # Set its management IP as primary
                    }

                    # Call the same function to sync the neighbor!
                    $neighborDevice = (Sync-DeviceToNetBox -DeviceInfo $neighborInfo -Headers $headers -NetboxBaseUrl $netboxbaseurl -SiteIdMap $siteIdMap -RoleIdMap $roleIdMap -DeviceTypeIdMap $deviceTypeIdMap -discoveredByCDP $true) | ConvertFrom-Json
                    $neighborDeviceId = $neighborDevice[0].id
                    if ($neighborDeviceId) {
                        # --- CREATE CABLE CONNECTION (LEVEL 1) ---
                        # Get the local interface ID
                        $localInterfaceUri = "$netboxbaseurl/dcim/interfaces/?device_id=$netboxDeviceId&name=$localInterfaceName"
                        $localInterfaceId = ((Invoke-WebRequest -Uri $localInterfaceUri -Headers $headers -SkipCertificateCheck).Content | ConvertFrom-Json).results[0].id

                        # Get the remote interface ID
                        $remoteInterfaceUri = "$netboxbaseurl/dcim/interfaces/?device_id=$neighborDeviceId&name=$remoteInterfaceName"
                        $remoteInterfaceId = ((Invoke-WebRequest -Uri $remoteInterfaceUri -Headers $headers -SkipCertificateCheck).Content | ConvertFrom-Json).results[0].id

                        if ($localInterfaceId -and $remoteInterfaceId) {
                            Connect-NetBoxInterfaces -InterfaceA_ID $localInterfaceId -InterfaceB_ID $remoteInterfaceId -Headers $headers -NetboxBaseUrl $netboxbaseurl
                        }
                        # --- END CABLE LOGIC ---

                        # RECURSIVE STEP: Discover neighbors of the neighbor
                        # You can add a depth counter here to prevent infinite loops
                        Write-Host "--> Discovering neighbors of neighbor '$($neighbor.remote_system_name)'"
                        
                        # Array of possible NAPALM passwords to try
                        $napalmPasswords = @( "2Twoleftfeetright", "d0ntgethacked!", "Get0ffmyl@wn") # Add more as needed
                        $napalmUsernames = @("lucksw", "lucklv15") # Add more as needed
                        $neighborNapalmUri = "$netboxbaseurl/plugins/netbox_napalm_plugin/napalmplatformconfig/$neighborDeviceId/napalm/?method=get_cdp_neighbors_detail"

                        $nCdpResponse = $null
                        foreach ($napalmUsername in $napalmUsernames) {
                            # Try each password for the current username
                            foreach ($napalmPassword in $napalmPasswords) {
                                $napalmHeaders = $headers.Clone()
                                $napalmHeaders["X-NAPALM-Username"] = $napalmUsername
                                $napalmHeaders["X-NAPALM-Password"] = $napalmPassword
                                try {
                                    $nCdpResponse = Invoke-WebRequest -Method Get -Uri $neighborNapalmUri -Headers $napalmHeaders -SkipCertificateCheck -ErrorAction Stop
                                    break # Success, exit loop
                                }
                                catch {
                                    Write-Warning "NAPALM authentication failed for Username '$napalmUsername' on neighbor '$($neighbor.remote_system_name)'."
                                    $nCdpResponse = $null
                                }
                            }
                        }

                        if ($nCdpResponse) {
                            $nCdpNeighbors = ($nCdpResponse.Content | ConvertFrom-Json).get_cdp_neighbors_detail
                            if ($nCdpNeighbors) {
                                $nCdpNeighbors.PSObject.Properties | ForEach-Object {
                                    foreach ($nNeighbor in $_.Value) {
                                        if ($nNeighbor.remote_system.platform -like "*-AP*") { $nNeighborRole = "Access Point" }
                                        else { $nNeighborRole = "Switch" }
                                        $nNeighborInfo = @{
                                            Name                   = $nNeighbor.remote_system_name
                                            SiteName               = $hostname.Split("-")[0]
                                            RoleName               = $nNeighborRole
                                            DeviceModel            = $nNeighbor.remote_system.platform
                                            Status                 = "active"
                                            Description            = "Discovered as CDP neighbor of $($neighbor.remote_system_name): $($nNeighbor.remote_system.neighbor_description)"
                                            Interfaces             = @( @{ Name = $nNeighbor.remote_interface; IPAddress = $nNeighbor.remote_ip_address; Type = "other" } )
                                            PrimaryIPInterfaceName = $nNeighbor.remote_interface
                                        }
                                        $nNeighborDeviceResult = Sync-DeviceToNetBox -DeviceInfo $nNeighborInfo -Headers $headers -NetboxBaseUrl $netboxbaseurl -SiteIdMap $siteIdMap -RoleIdMap $roleIdMap -DeviceTypeIdMap $deviceTypeIdMap -discoveredByCDP $true
                                        $nNeighborDeviceId = ($nNeighborDeviceResult | ConvertFrom-Json)[0].id

                                        if ($nNeighborDeviceId) {
                                            # --- CREATE CABLE CONNECTION (LEVEL 2) ---
                                            $nLocalInterfaceName = $_.Name # This is the interface on the first neighbor
                                            $nRemoteInterfaceName = $nNeighbor.remote_port # This is the interface on the second neighbor

                                            # Get the local interface ID (on the first neighbor device)
                                            $nLocalInterfaceUri = "$netboxbaseurl/dcim/interfaces/?device_id=$neighborDeviceId&name=$nLocalInterfaceName"
                                            $nLocalInterfaceId = ((Invoke-WebRequest -Uri $nLocalInterfaceUri -Headers $headers -SkipCertificateCheck).Content | ConvertFrom-Json).results[0].id

                                            # Get the remote interface ID (on the second neighbor device)
                                            $nRemoteInterfaceUri = "$netboxbaseurl/dcim/interfaces/?device_id=$nNeighborDeviceId&name=$nRemoteInterfaceName"
                                            $nRemoteInterfaceId = ((Invoke-WebRequest -Uri $nRemoteInterfaceUri -Headers $headers -SkipCertificateCheck).Content | ConvertFrom-Json).results[0].id

                                            if ($nLocalInterfaceId -and $nRemoteInterfaceId) {
                                                Connect-NetBoxInterfaces -InterfaceA_ID $nLocalInterfaceId -InterfaceB_ID $nRemoteInterfaceId -Headers $headers -NetboxBaseUrl $netboxbaseurl
                                            }
                                            # --- END CABLE LOGIC ---
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    catch {
        Write-Warning "Failed to fetch CDP neighbors for $hostname : $_"
    }

        
                

    # 5.3 Fetch and Sync ARP entries (kept as is)
    $arpUri = "$baseuri/device/arp?deviceId=$systemIp"
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
