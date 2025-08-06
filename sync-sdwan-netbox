param(
    [switch]$publicIPonly
)

# --- Step 1: Authenticate to SD-WAN and get JSESSIONID ---
$baseURI = "https://VMANAGEINSTANCEID.sdwan.cisco.com/dataservice"
$response = Invoke-WebRequest -Method Post `
    -Uri "https://vmanage-2025324.sdwan.cisco.com/j_security_check" `
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
                enabled = $isEnabled
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
                assigned_object_id = $netboxInterfaceId
            }

            if ($ipCheck.count -gt 0) {
                # IP exists, PATCH it to ensure it's assigned to the correct interface
                $netboxIpId = $ipCheck.results[0].id
                # Only patch if the assignment is different
                if ($ipCheck.results[0].assigned_object.id -ne $netboxInterfaceId) {
                    Invoke-WebRequest -Method Patch -Uri "$netboxbaseurl/ipam/ip-addresses/$netboxIpId/" -Headers $headers -Body ($ipPayload | ConvertTo-Json) -SkipCertificateCheck
                    Write-Host "Updated IP assignment for $($interface.'ip-address')"
                }
            } else {
                # IP does not exist, POST it
                $ipPayload.address = $ipAddress
                $ipPayload.status = "active"
                Invoke-WebRequest -Method Post -Uri "$netboxbaseurl/ipam/ip-addresses/" -Headers $headers -Body ($ipPayload | ConvertTo-Json) -SkipCertificateCheck
                Write-Host "Created IP Address: $($interface.'ip-address')"
            }
        }
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
                        address = $arpIp
                        status = "active"
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
