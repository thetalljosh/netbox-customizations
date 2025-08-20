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
    # if ( $devicecheck.results[0].role.name -eq "Router" -and $discoveredByCDP) {
    #     Write-Host "Device $hostname is a Router and was discovered by CDP. Skipping update to avoid overwriting role."
    #     return $null
    # }

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
        type           = "cat6"
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
        status         = "connected"
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

function Invoke-CiscoPsirtCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Versions
    )

    # --- Script Configuration ---
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    $ApiTokenUrl = "https://id.cisco.com/oauth2/default/v1/token"
    $ApiGetAdvisoriesUrl = "https://apix.cisco.com/security/advisories/v2/OSType/iosxe?version="

    # --- Load Credentials ---
    # $credsFile = Join-Path $PSScriptRoot "psirtkeys.ps1"
    $credsFile = '.\psirtkeys.ps1'
    if (Test-Path $credsFile) {
        . $credsFile # Dot-source to load $CLIENT_ID and $CLIENT_SECRET
    }
    else {
        throw "Credential file not found! Please create 'psirtkeys.ps1'."
    }

    # --- Helper Functions ---
    function Get-ApiToken {
        param($CLIENT_ID, $CLIENT_SECRET)
        $body = @{
            grant_type    = "client_credentials"
            client_id     = $CLIENT_ID
            client_secret = $CLIENT_SECRET
        }
        try {
            $response = Invoke-RestMethod -Uri $ApiTokenUrl -Method Post -Body $body -ErrorAction Stop
            Write-Host "PSIRT API Authentication Successful" -ForegroundColor Green
            return $response.access_token
        }
        catch {
            throw "PSIRT API Authentication Failed. Check credentials. Details: $($_.Exception.Message)"
        }
    }

    # --- Main Logic ---
    Write-Host "`nQuerying Cisco PSIRT openVuln API..."
    $apiToken = Get-ApiToken -CLIENT_ID $script:CLIENT_ID -CLIENT_SECRET $script:CLIENT_SECRET
    
    $allAdvisories = [System.Collections.Generic.List[object]]::new()
    foreach ($version in $Versions) {
        $headers = @{ "Authorization" = "Bearer $apiToken"; "Accept" = "application/json" }
        $url = $ApiGetAdvisoriesUrl + $version.Trim()
        
        $result = [PSCustomObject]@{
            Version    = $version.Trim()
            Advisories = @()
        }

        try {
            $response = Invoke-RestMethod -Uri $url -Method Get -Headers $headers -ErrorAction Stop
            if ($response.advisories) {
                $result.Advisories = $response.advisories
            }
        }
        catch {
            Write-Warning "Could not retrieve advisories for version '$($version)': $($_.Exception.Message)"
        }
        $allAdvisories.Add($result)
    }
    
    return $allAdvisories
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
$netboxbaseurl = "https://NETBOX.CONTOSO.net/api"
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
                        $napalmPasswords = @( "CONTOSO", "CONTOSO!", "CONTOSO?") # Add more as needed
                        $napalmUsernames = @("CONTOSO", "CONTOSO") # Add more as needed
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
                                            Description            = "$($nNeighbor.remote_system.neighbor_description)"
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

#==============================================================================
#   Vulnerability Scanning and Assignment Workflow
#==============================================================================
Write-Host "`n--- Starting Vulnerability Scan Workflow ---"

# 1. Import the PSIRT checker function
. (Join-Path $PSScriptRoot "Get-CiscoPsirt.ps1")

# 2. Get all relevant devices from NetBox (Switches and APs)
Write-Host "Fetching discovered devices from NetBox..."
$allDiscoveredDevices = Invoke-RestMethod -Method Get -Uri "$netboxbaseurl/dcim/devices/?limit=0" -Headers $headers -SkipCertificateCheck
$allDiscoveredDevices = $allDiscoveredDevices.results | Where-Object { $_.role.name -in @("Switch", "Access Point", "Router") -and $_.description -match "Version\s+[0-9\.]+" }
# 3. Parse versions and group devices
Write-Host "Parsing software versions and grouping devices..."
$versionsToDevicesMap = @{}
$regex = [regex]::new("Version\s+([0-9\.]+)")
foreach ($device in $allDiscoveredDevices) {
    $match = $regex.Match($device.description)
    if ($match.Success) {
        $version = $match.Groups[1].Value
        if (-not $versionsToDevicesMap.ContainsKey($version)) {
            $versionsToDevicesMap[$version] = [System.Collections.Generic.List[int]]::new()
        }
        $versionsToDevicesMap[$version].Add($device.id)
    }
}

if ($versionsToDevicesMap.Keys.Count -eq 0) {
    Write-Host "No devices with parsable IOS versions found. Exiting vulnerability scan." -ForegroundColor Yellow
    return
}


# 4. Call the PSIRT API with the unique versions found
$uniqueVersions = $versionsToDevicesMap.Keys
$vulnerabilityReport = Invoke-CiscoPsirtCheck -Versions $uniqueVersions

# 4a. Pre-fetch all existing vulnerability assignments for the devices we're checking
Write-Host "Fetching all existing vulnerability assignments from NetBox for comparison..."
$allDeviceIds = $versionsToDevicesMap.Values | ForEach-Object { $_ } | Select-Object -Unique
$existingAssignmentsQuery = $allDeviceIds | ForEach-Object { "asset_id=$_" } | Join-String -Separator '&'

# Use limit=0 to get all results without pagination
$allExistingAssignments = Invoke-RestMethod -Method Get -Uri "$netboxbaseurl/plugins/nb_risk/vulnerabilityassignment/?$existingAssignmentsQuery&limit=0" -Headers $headers -SkipCertificateCheck
$allExistingVulns = Invoke-RestMethod -Method Get -Uri "$netboxbaseurl/plugins/nb_risk/vulnerability/?limit=0" -Headers $headers -SkipCertificateCheck
$allExistingVulns = $allExistingVulns.results 

# Organize the existing assignments by device ID for easy lookup later
$existingAssignmentsMap = @{}
foreach ($assignment in $allExistingAssignments.results) {
    # --- FIX: Add a null check to prevent errors from broken relationships in NetBox ---
    if ($assignment.asset -and $assignment.vulnerability) {
        $deviceId = "$($assignment.asset.id)" # Ensure deviceId is always a string
        if (-not $existingAssignmentsMap.ContainsKey($deviceId)) {
            $existingAssignmentsMap[$deviceId] = @{}
        }
        # Store the vuln name and the ID of the assignment object itself
        $existingAssignmentsMap[$deviceId][$assignment.vulnerability] = $assignment.id
    }
}

# 5. Process the report: Create vulnerabilities and assignments in NetBox
# $vulnerabilityNameToIdMap = @{} # Cache to avoid duplicate lookups/creations

foreach ($reportItem in $vulnerabilityReport) {
    $version = $reportItem.Version
    if ($reportItem.Advisories.Count -eq 0) {
        Write-Host "No vulnerabilities found for version $version."
        continue
    }

    Write-Host "Processing $($reportItem.Advisories.Count) vulnerabilities for version $version..."
    $deviceIds = $versionsToDevicesMap[$version]

    foreach ($advisory in $reportItem.Advisories) {
        $originalVulnName = $advisory.advisoryId
        if ($originalVulnName.Length -gt 100) {
            $originalVulnName = $originalVulnName.Substring(0, 100)
        }
        
        $netboxVulnObject = $null

        # $vulnCheckUri = "$netboxbaseurl/plugins/nb_risk/vulnerability/?name__ie=$originalVulnName"
        # $existingVulnResponse = Invoke-RestMethod -Method Get -Uri $vulnCheckUri -Headers $headers -SkipCertificateCheck

        [bool]$vulnExists = $false
        if($allExistingVulns.name -contains $originalVulnName) {
            $vulnExists = $true
        }
        $advisoryNotes = "Discovered via Cisco PSIRT API on $(Get-Date -Format 'yyyy-MM-dd') `r`n`r`n Advisory URL: $($advisory.publicationURL) `r`n`r`n CVSS: $($advisory.cvssBaseScore) `r`n`r`n First Fixed: $($advisory.firstFixed -join ', ') `r`n`r`n Risk: $($advisory.sir) `r`n`r`n Advisory Summary: $(($advisory.summary | ConvertFrom-Html).innertext)"

        if ($vulnExists) {
            $vulnURI = $allExistingVulns | Where-Object { $_.name -eq $originalVulnName } | Select-Object -ExpandProperty url
            # --- UPDATE EXISTING VULNERABILITY ---
            Write-Host "Vulnerability '$originalVulnName' already exists. Updating..."
            $updatePayload = @{
                description = "CVSS: $($advisory.cvssBaseScore) `n First Fixed: $($advisory.firstFixed -join ', ') `n Risk: $($advisory.sir)"
                notes       = $advisoryNotes
            } | ConvertTo-Json
            # Use the object's URL property for the PATCH URI
            $netboxVulnObject = Invoke-RestMethod -Method Patch -Uri $vulnURI -Headers $headers -Body $updatePayload -SkipCertificateCheck
        }
        else {
            # --- CREATE NEW VULNERABILITY ---
            $description = "CVSS: $($advisory.cvssBaseScore) `n First Fixed: $($advisory.firstFixed -join ', ') `n Risk: $($advisory.sir)"
            if ($description.Length -gt 200) { $description = $description.Substring(0, 200) }
                
            $vulnPayload = @{
                name        = $originalVulnName
                cve         = ($advisory.cves | Select-Object -First 1)
                description = $description
                notes       = $advisoryNotes
            } | ConvertTo-Json
                
            Write-Host "Creating new vulnerability '$originalVulnName' in NetBox..."
            try {
                $netboxVulnObject = Invoke-RestMethod -Method Post -Uri "$netboxbaseurl/plugins/nb_risk/vulnerability/" -Headers $headers -Body $vulnPayload -SkipCertificateCheck -ErrorAction Stop
            }
            catch {
                Write-Warning "Failed to create vulnerability '$originalVulnName': $($_.Exception.Message)"
            }
        }

        # --- ASSIGN VULNERABILITY ---
        if (-not $netboxVulnObject) {
            Write-Warning "Failed to find or create vulnerability '$originalVulnName'. Skipping assignment."
            continue
        }

        foreach ($deviceId in $deviceIds) {
            $assignmentPayload = @{
                asset_object_type = "dcim.device"
                asset_id          = $deviceId
                vulnerability     = $netboxVulnObject.name 
            } | ConvertTo-Json
            #First, check if this assignment already exists
            if ($existingAssignmentsMap.ContainsKey($deviceId) -and $existingAssignmentsMap[$deviceId].ContainsKey($netboxVulnObject.name)) {
                Write-Host "Vulnerability '$($netboxVulnObject.name)' already assigned to device ID $deviceId. Skipping assignment."
                continue
            }
            Write-Host "Assigning vulnerability '$($netboxVulnObject.name)' to device ID $deviceId..."
            try {
                Invoke-RestMethod -Method Post -Uri "$netboxbaseurl/plugins/nb_risk/vulnerabilityassignment/" -Headers $headers -Body $assignmentPayload -SkipCertificateCheck -ErrorAction Stop
            }
            catch {
                Write-Warning "Could not assign vulnerability to device ID $deviceId : $($_.Exception.Message)"
            }
        }
    }

    # 6. Prune Stale Vulnerability Assignments
    Write-Host "Pruning stale vulnerability assignments for version $version..."

    # Get the definitive list of vulnerability names that SHOULD be assigned for this version
    $shouldBeVulnNames = $reportItem.Advisories | ForEach-Object {
        $name = $_.advisoryId
        if ($name.Length -gt 100) { $name = $name.Substring(0, 100) }
        $name
    } | Select-Object -Unique

    # For each device running this version, check for and remove outdated assignments
    $deviceIdsForThisVersion = $versionsToDevicesMap[$version]
    foreach ($deviceId in $deviceIdsForThisVersion) {
        # Check if we have any existing assignment data for this device
        if (-not $existingAssignmentsMap.ContainsKey($deviceId)) {
            continue # No existing assignments, so nothing to prune.
        }

        $existingVulnNamesForDevice = $existingAssignmentsMap[$deviceId].Keys
        
        # Find assignments that exist in NetBox but are NOT in the latest PSIRT report
        $assignmentsToDelete = Compare-Object -ReferenceObject $shouldBeVulnNames -DifferenceObject $existingVulnNamesForDevice | Where-Object { $_.SideIndicator -eq '=>' } | Select-Object -ExpandProperty InputObject

        foreach ($vulnNameToDelete in $assignmentsToDelete) {
            $assignmentIdToDelete = $existingAssignmentsMap[$deviceId][$vulnNameToDelete]
            Write-Host "--> Removing stale assignment of '$vulnNameToDelete' from device ID $deviceId (Assignment ID: $assignmentIdToDelete)"
            try {
                $deleteUri = "$netboxbaseurl/plugins/nb_risk/vulnerabilityassignment/$assignmentIdToDelete/"
                Invoke-RestMethod -Method Delete -Uri $deleteUri -Headers $headers -SkipCertificateCheck -ErrorAction Stop
            }
            catch {
                Write-Warning "Failed to delete assignment ID $assignmentIdToDelete : $($_.Exception.Message)"
            }
        }
    }
 
}

Write-Host "`n--- Vulnerability Scan Workflow Complete ---" -ForegroundColor Green
