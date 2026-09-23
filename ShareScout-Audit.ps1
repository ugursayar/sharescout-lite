<#
.SYNOPSIS
    ShareScout - Microsoft 365 oversharing & permissions audit. Finds who can see what across
    SharePoint, OneDrive and Teams: Anyone links, "Everyone except external users", guests,
    broken permission inheritance, ownerless sites, sensitivity-label gaps - and scores each
    site's Copilot exposure.

.DESCRIPTION
    Runs entirely inside YOUR tenant (Microsoft Graph PowerShell SDK + PnP.PowerShell, read-only).
    No data ever leaves your environment - ShareScout has no servers and collects nothing.

    Produces:
      * CSV exports for each finding (for remediation / site access reviews)
      * A console summary

    Findings:
      * Anyone links            (anonymous sharing links: where, edit/view, expiry)
      * Everyone / EEEU         (sites & items open to the whole organisation)

.PARAMETER Sites
    Restrict the per-site scan to these site URLs. Default: all sites returned by the tenant.

.PARAMETER MaxItemsPerSite
    Stop scanning a site's items after this many list items. Default 50000. The report flags
    truncated sites.

.PARAMETER SkipItemScan
    Skip the item-level walk (unique permissions + sharing links). Sections 2, 3, 5, 6, 8 only.
    Fast first look on large tenants.

.PARAMETER OutputPath
    Folder for the report + CSVs. Default: .\ShareScout-Report-<timestamp>

.PARAMETER Lite
    Free mode: tenant summary + Anyone-links CSV + EEEU-sites CSV only (no HTML report).

.PARAMETER MockDataPath
    Internal/testing: load tenant data from a JSON file instead of calling Graph / PnP.

.EXAMPLE
    .\ShareScout-Audit.ps1 -SkipItemScan

.NOTES
    ShareScout  |  sharescout.dev  |  read-only, runs in your tenant.
#>

[CmdletBinding()]
param(
    [string[]] $Sites,
    [int]      $MaxItemsPerSite = 50000,
    [switch]   $SkipItemScan,
    [string]   $OutputPath,
    [switch]   $Lite,
    [string]   $MockDataPath,
    [string]   $PnPClientId,
    [switch]   $DeviceLogin
)

$ErrorActionPreference = 'Stop'
$script:Version = '1.0.1'
$script:Edition = 'Lite'   # build edition (set per package): Lite | Solo | Pro
$nowUtc = (Get-Date).ToUniversalTime()
$script:EmptyGuid = '00000000-0000-0000-0000-000000000000'

# ----------------------------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------------------------
function Write-Step { param($Msg) Write-Host "[ShareScout] $Msg" -ForegroundColor Cyan }
function Write-Warn { param($Msg) Write-Host "[ShareScout] $Msg" -ForegroundColor Yellow }

function Connect-ShareScoutGraph {
    # WAM (the Windows broker) needs a parent window handle; hosts without one (VS Code / embedded
    # terminals, remote sessions, scheduled runs) fail with 'A window handle must be configured'.
    param([string[]]$Scopes, [switch]$Device)
    if ($Device) { Connect-MgGraph -Scopes $Scopes -UseDeviceAuthentication -NoWelcome; return }
    try { Connect-MgGraph -Scopes $Scopes -NoWelcome }
    catch {
        if ($_.Exception.Message -match 'window handle|WAM|broker') {
            Write-Warn "Browser sign-in unavailable in this host - falling back to device code."
            Connect-MgGraph -Scopes $Scopes -UseDeviceAuthentication -NoWelcome
        } else { throw }
    }
}

function Connect-ShareScoutPnP {
    # PnP.PowerShell 3.x device login fails ('Unable to connect using provided arguments') without -Tenant.
    param([string]$Url, [string]$ClientId, [string]$Tenant, [switch]$Device)
    if ($Device) { Connect-PnPOnline -Url $Url -DeviceLogin -ClientId $ClientId -Tenant $Tenant }
    else { Connect-PnPOnline -Url $Url -Interactive -ClientId $ClientId -Tenant $Tenant }
}

function Export-ShareScoutCsv {
    # Export-Csv writes a 0-byte file for an empty array, so an all-clear run looks like a broken one.
    # Emit the header row instead, keeping the documented columns.
    param($Rows, [string]$Path, [string[]]$Columns)
    $arr = @($Rows)
    if ($arr.Count -eq 0) { ('"' + ($Columns -join '","') + '"') | Out-File -FilePath $Path -Encoding utf8; return }
    $arr | Export-Csv -Path $Path -NoTypeInformation -Encoding utf8
}


function Test-BroadPrincipal {
    # Everyone / Everyone except external users / All Users claims
    param([string]$LoginName, [string]$Title)
    $l = [string]$LoginName; $t = [string]$Title
    return ($l -like 'c:0(.s|true' -or $l -like 'c:0-.f|rolemanager|spo-grid-all-users/*' -or
            $l -like '*spo-grid-all-users*' -or $t -eq 'Everyone' -or $t -eq 'Everyone except external users' -or
            $t -like 'All Users*')
}

function Get-PrincipalUpn {
    # 'i:0#.f|membership|someone_gmail.com#ext#@contoso.onmicrosoft.com' -> the part after the last '|'
    param($Principal)
    if ($Principal.Email) { return [string]$Principal.Email }
    $l = [string]$Principal.LoginName
    if ($l -match '\|([^|]+)$') { return $Matches[1] }
    return $l
}

function Get-SensitivityLabelMap {
    # Get-PnPTenantSite reports SensitivityLabel as a label GUID, so the Confidential|Restricted|
    # Secret|Internal mismatch rule can never match it. Resolve the names once per run; on any
    # failure (no permission, no labels in the tenant) return an empty map and keep the GUID.
    $map = @{}
    try {
        $labels = @(Get-PnPAvailableSensitivityLabel -ErrorAction Stop)
        foreach ($l in $labels) {
            $id = [string]$l.Id
            $name = [string]$l.DisplayName
            if (-not $name) { $name = [string]$l.Name }
            if ($id -and $name) { $map[$id.ToLower()] = $name }
        }
        if ($map.Count -gt 0) { Write-Step "Resolved $($map.Count) sensitivity label name(s)." }
        else { Write-Warn "Tenant publishes no sensitivity labels - any site label is reported by GUID." }
    } catch {
        Write-Warn "Sensitivity label names unavailable ($(([string]$_.Exception.Message) -split "`r?`n" | Select-Object -First 1)) - labels are reported by GUID."
    }
    return $map
}

function Resolve-SensitivityLabel {
    # Passes any non-GUID value straight through, so mock data (which carries display names) is unaffected.
    param([string]$Value, $Map)
    if (-not $Value) { return '' }
    if ($Map -and $Map.ContainsKey($Value.ToLower())) { return $Map[$Value.ToLower()] }
    return $Value
}

function Get-SiteKind {
    param($Template, $Url)
    if ($Url -like '*-my.sharepoint.com/personal/*' -or $Template -like 'SPSPERS*' -or $Template -like 'SPSMSITEHOST*') { return 'OneDrive' }
    if ($Template -like 'GROUP*')   { return 'Team site (M365 group)' }
    if ($Template -like 'TEAMCHANNEL*') { return 'Teams channel site' }
    if ($Template -like 'SITEPAGEPUBLISHING*') { return 'Communication site' }
    return 'Site'
}

# ----------------------------------------------------------------------------------------------
# Data acquisition (Graph + PnP, OR mock)
# ----------------------------------------------------------------------------------------------
function Get-TenantData {
    param([string]$MockPath)

    if ($MockPath) {
        Write-Step "Loading MOCK data from $MockPath"
        $raw = Get-Content -Path $MockPath -Raw | ConvertFrom-Json
        # Mock dates are absolute, so age/inactivity math runs against the mock's own asOf instead of
        # the clock; otherwise the demo output (and the published sample figures) drift day by day.
        if ($raw.asOf) { $script:nowUtc = ([datetime]$raw.asOf).ToUniversalTime() }
        return $raw
    }

    Write-Step "Connecting to Microsoft Graph (read-only)..."
    $scopes = @('User.Read.All','Group.Read.All','Directory.Read.All','Sites.Read.All','AuditLog.Read.All','Organization.Read.All')
    try { Import-Module Microsoft.Graph.Authentication -ErrorAction Stop }
    catch { throw "Microsoft Graph PowerShell SDK not installed. Run:  Install-Module Microsoft.Graph -Scope CurrentUser" }
    Connect-ShareScoutGraph -Scopes $scopes -Device:$DeviceLogin
    $org = Get-MgOrganization
    $tenantName = ($org.VerifiedDomains | Where-Object { $_.IsInitial } | Select-Object -First 1).Name
    if (-not $tenantName) { $tenantName = $org.VerifiedDomains[0].Name }
    $tenantPrefix = $tenantName.Split('.')[0]
    $adminUrl = "https://$tenantPrefix-admin.sharepoint.com"

    Write-Step "Connecting to SharePoint admin ($adminUrl) via PnP.PowerShell (read-only)..."
    try { Import-Module PnP.PowerShell -ErrorAction Stop }
    catch { throw "PnP.PowerShell not installed. Run:  Install-Module PnP.PowerShell -Scope CurrentUser" }
    if (-not $PnPClientId) {
        throw "PnP.PowerShell requires an Entra app registration for interactive login. See README 'One-time setup' (Register-PnPEntraIDAppForInteractiveLogin), then pass -PnPClientId <appId>."
    }
    Connect-ShareScoutPnP -Url $adminUrl -ClientId $PnPClientId -Tenant $tenantName -Device:$DeviceLogin

    $labelMap = Get-SensitivityLabelMap

    # --- Tenant pass ---
    Write-Step "Reading tenant sharing settings + site list..."
    $tenant = Get-PnPTenant
    $tenantSites = Get-PnPTenantSite -Detailed -IncludeOneDriveSites | Where-Object { $_.Template -notlike 'REDIRECT*' -and $_.Template -notlike 'SRCHCEN*' -and $_.Template -notlike 'APPCATALOG*' }
    if ($Sites) { $tenantSites = $tenantSites | Where-Object { $Sites -contains $_.Url } }

    $guestObjs = @{}
    $signInActivityAvailable = $false
    $groupsByMail = @{}

    # --- Per-site pass ---
    $siteRecords = @()
    $i = 0
    foreach ($s in $tenantSites) {
        $i++
        Write-Step ("Site {0}/{1}: {2}" -f $i, $tenantSites.Count, $s.Url)
        $rec = [ordered]@{
            url = $s.Url; title = $(if ($s.Title) { $s.Title } else { $s.Url }); template = $s.Template; kind = (Get-SiteKind $s.Template $s.Url)
            sharingCapability = [string]$s.SharingCapability
            sensitivityLabel = $(if ("$($s.SensitivityLabel)" -ne $script:EmptyGuid) { Resolve-SensitivityLabel ([string]$s.SensitivityLabel) $labelMap } else { '' })
            groupEmail = $(if ("$($s.GroupId)" -and "$($s.GroupId)" -ne $script:EmptyGuid) { [string]$s.GroupId } else { '' }); owner = $s.Owner; itemCount = 0; itemScanTruncated = $false
            admins = @(); broadPrincipals = @(); guestUsers = @(); uniqueLists = 0; uniqueItems = 0; anyoneLinks = @(); eeeuItems = @()
            storageGB = [math]::Round(($s.StorageUsageCurrent / 1024), 1); lastContentModified = $s.LastContentModifiedDate
        }
        try {
            Connect-ShareScoutPnP -Url $s.Url -ClientId $PnPClientId -Tenant $tenantName -Device:$DeviceLogin

            # Who actually holds permission on this web. Get-PnPUser cannot answer that: it returns the
            # site's User Information List, which carries Everyone and EEEU on every site whether or not
            # they were ever granted anything.
            $web = Get-PnPWeb
            $webRas = @(); try { $webRas = Get-PnPProperty -ClientObject $web -Property RoleAssignments } catch {}
            $permittedGroupIds = @{}
            foreach ($ra in $webRas) {
                $mem = $null; try { $mem = Get-PnPProperty -ClientObject $ra -Property Member } catch {}
                if (-not $mem) { continue }
                $roles = @()
                try { $roles = @((Get-PnPProperty -ClientObject $ra -Property RoleDefinitionBindings) | ForEach-Object { $_.Name } | Where-Object { $_ -ne 'Limited Access' }) } catch {}
                if ($roles.Count -eq 0) { continue }
                if ($mem.PrincipalType -eq 'SharePointGroup') { $permittedGroupIds[[string]$mem.Id] = $true; continue }
                $via = "direct: $($roles -join ',')"
                if (Test-BroadPrincipal $mem.LoginName $mem.Title) { $rec.broadPrincipals += "$($mem.Title) ($via)" }
                if ($mem.LoginName -like '*#ext#*' -or $mem.LoginName -like '*urn:spo:guest*') { $rec.guestUsers += @{ upn = (Get-PrincipalUpn $mem); via = $via } }
            }

            # SharePoint groups, but only those the web actually grants a permission level to.
            foreach ($grp in (Get-PnPGroup)) {
                if (-not $permittedGroupIds.ContainsKey([string]$grp.Id)) { continue }
                $members = @(); try { $members = Get-PnPGroupMember -Group $grp } catch {}
                foreach ($m in $members) {
                    if (Test-BroadPrincipal $m.LoginName $m.Title) { $rec.broadPrincipals += "$($m.Title) via $($grp.Title)" }
                    if ($m.LoginName -like '*#ext#*' -or $m.LoginName -like '*urn:spo:guest*') { $rec.guestUsers += @{ upn = (Get-PrincipalUpn $m); via = $grp.Title } }
                }
            }
            $rec.broadPrincipals = @($rec.broadPrincipals | Select-Object -Unique)

            if (-not $SkipItemScan) {
                $lists = Get-PnPList | Where-Object { $_.Hidden -eq $false -and ($_.BaseTemplate -eq 101 -or $_.BaseTemplate -eq 100 -or $_.BaseTemplate -eq 700) }
                foreach ($list in $lists) {
                    $lu = $false; try { $lu = (Get-PnPProperty -ClientObject $list -Property HasUniqueRoleAssignments) } catch {}
                    if ($lu) { $rec.uniqueLists++ }
                    $count = 0
                    # HasUniqueRoleAssignments is a CSOM property, NOT a list field: passing it to -Fields
                    # leaves it empty and every item looks inherited. -Includes loads it with the same
                    # paged query (~35x faster than a Get-PnPProperty round trip per item).
                    $items = Get-PnPListItem -List $list -PageSize 2000 -Fields 'ID','FileRef','FSObjType' -Includes 'HasUniqueRoleAssignments'
                    foreach ($it in $items) {
                        $count++
                        if ($count -gt $MaxItemsPerSite) { $rec.itemScanTruncated = $true; break }
                        if ($it.HasUniqueRoleAssignments -eq $true) {
                            $rec.uniqueItems++
                            $ras = @(); try { $ras = Get-PnPProperty -ClientObject $it -Property RoleAssignments } catch {}
                            $isFolder = ($it['FSObjType'] -eq 1)
                            $fileLinks = $null   # link metadata is fetched once per item, and only if it has one
                            foreach ($ra in $ras) {
                                $mem = $null; try { $mem = Get-PnPProperty -ClientObject $ra -Property Member } catch {}
                                if ($mem -and (Test-BroadPrincipal $mem.LoginName $mem.Title)) { $rec.eeeuItems += @{ path = $it['FileRef']; principal = $mem.Title } }
                                if ($mem -and $mem.LoginName -like 'SharingLinks.*') {
                                    # Sharing link principal: SharingLinks.<docGuid>.<type>.<linkGuid>
                                    # type: AnonymousEdit | AnonymousView | OrganizationEdit | OrganizationView | Flexible
                                    $parts = $mem.LoginName.Split('.')
                                    $ltype = if ($parts.Count -ge 3) { $parts[2] } else { 'Unknown' }
                                    if ($ltype -like 'Anonymous*') {
                                        if ($null -eq $fileLinks) {
                                            $fileLinks = @{}
                                            try {
                                                $sls = if ($isFolder) { Get-PnPFolderSharingLink -Identity $it['FileRef'] } else { Get-PnPFileSharingLink -Identity $it['FileRef'] }
                                                foreach ($sl in @($sls)) { $fileLinks[[string]$sl.Id] = $sl }
                                            } catch {}
                                        }
                                        $linkId = if ($parts.Count -ge 4) { [string]$parts[3] } else { '' }
                                        $expires = $null
                                        if ($linkId -and $fileLinks.ContainsKey($linkId)) { $expires = $fileLinks[$linkId].ExpirationDateTime }
                                        # no API surfaces a sharing link's creation date, so Created/AgeDays stay blank
                                        $rec.anyoneLinks += @{ path = $it['FileRef']; linkType = $ltype; isFolder = $isFolder; created = $null; expires = $expires }
                                    }
                                }
                            }
                        }
                    }
                    $rec.itemCount += $count
                    if ($rec.itemScanTruncated) { break }
                }
            }
        } catch {
            Write-Warn ("  skipped ({0})" -f $_.Exception.Message)
            $rec.error = $_.Exception.Message
        }
        $siteRecords += [pscustomobject]$rec
    }

    return [pscustomobject]@{
        organization = [pscustomobject]@{ displayName = $org.DisplayName; id = $org.Id }
        tenant = [pscustomobject]@{
            sharingCapability = [string]$tenant.SharingCapability
            requireAnonymousLinksExpireInDays = $tenant.RequireAnonymousLinksExpireInDays
            defaultSharingLinkType = [string]$tenant.DefaultSharingLinkType
            entraP1 = $signInActivityAvailable
        }
        guests = @($guestObjs.Values | ForEach-Object { [pscustomobject]$_ })
        groups = @($groupsByMail.GetEnumerator() | ForEach-Object { [pscustomobject](@{ mail = $_.Key } + $_.Value) })
        sites  = $siteRecords
        itemScanSkipped = [bool]$SkipItemScan
    }
}

# ----------------------------------------------------------------------------------------------
# Analysis
# ----------------------------------------------------------------------------------------------
function Invoke-Analysis {
    param($Data)

    $anyone = @(); $eeeuSites = @()

    foreach ($s in $Data.sites) {
        $isOneDrive = ($s.kind -eq 'OneDrive')
        $broad = @($s.broadPrincipals)
        $siteAnyone = @($s.anyoneLinks)

        # 1. Anyone links
        foreach ($l in $siteAnyone) {
            $age = $null; if ($l.created) { try { $age = [int]($nowUtc - [datetime]$l.created).TotalDays } catch {} }
            $anyone += [pscustomobject]@{
                Site = $s.title; Url = $s.url; Path = $l.path; Type = $(if ($l.linkType -eq 'AnonymousEdit') { 'Anyone can edit' } elseif ($l.linkType -eq 'AnonymousView') { 'Anyone can view' } else { [string]$l.linkType }); Folder = [bool]$l.isFolder
                Created = if ($l.created) { ([datetime]$l.created).ToString('yyyy-MM-dd') } else { '' }
                Expires = if ($l.expires) { ([datetime]$l.expires).ToString('yyyy-MM-dd') } else { 'never' }
                AgeDays = if ($null -ne $age) { $age } else { '' }
            }
        }
        # 2. EEEU. OneDrive is held out so the headline's numerator and denominator cover the same
        #    population (NonOneDriveCount); a whole-org grant on a personal OneDrive goes to advisory
        #    instead. The My Site host is skipped entirely - EEEU Read there is how OneDrive provisions.
        if ($broad.Count -gt 0) {
            if (-not $isOneDrive) {
                $eeeuSites += [pscustomobject]@{ Site=$s.title; Url=$s.url; Kind=$s.kind; Via=($broad -join '; '); Items=$s.itemCount; Label=$s.sensitivityLabel }
            }
        }
    }
    $anyoneNoExpiry = @($anyone | Where-Object { $_.Expires -eq 'never' }).Count
    $distinctGuests = @($Data.sites | ForEach-Object { @($_.guestUsers) } | ForEach-Object { $_.upn } | Where-Object { $_ } | Select-Object -Unique).Count
    $nonOd = @($Data.sites | Where-Object { $_.kind -ne 'OneDrive' }).Count

    $result = [ordered]@{
        Org=$Data.organization; Tenant=$Data.tenant
        SiteCount=@($Data.sites).Count; NonOneDriveCount=$nonOd
        Anyone=@($anyone | Sort-Object @{e={ if ($_.Expires -eq 'never') { 0 } else { 1 } }}, @{e={ $_.Created }}); AnyoneNoExpiry=$anyoneNoExpiry
        EeeuSites=@($eeeuSites | Sort-Object Items -Descending)
        DistinctGuests=$distinctGuests
        ItemScanSkipped=[bool]$Data.itemScanSkipped
        TruncatedSites=@($Data.sites | Where-Object { $_.itemScanTruncated }).Count
        Errors=@($Data.sites | Where-Object { $_.error }).Count
    }
    return [pscustomobject]$result
}

# ----------------------------------------------------------------------------------------------
# Reporting
# ----------------------------------------------------------------------------------------------

# ----------------------------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------------------------
Write-Host ""
Write-Host "  ShareScout v$script:Version - Microsoft 365 oversharing & permissions audit" -ForegroundColor Green
Write-Host "  Read-only. Runs in your tenant. Nothing leaves your environment." -ForegroundColor DarkGray
Write-Host ""

if (-not $OutputPath) { $OutputPath = Join-Path (Get-Location) ("ShareScout-Report-" + $nowUtc.ToString('yyyyMMdd-HHmmss')) }
New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null

$data = Get-TenantData -MockPath $MockDataPath
$R    = Invoke-Analysis -Data $data

# CSV exports (always)
Export-ShareScoutCsv $R.Anyone    (Join-Path $OutputPath 'anyone-links.csv') @('Site','Url','Path','Type','Folder','Created','Expires','AgeDays')
Export-ShareScoutCsv $R.EeeuSites (Join-Path $OutputPath 'eeeu-sites.csv')  @('Site','Url','Kind','Via','Items','Label')

if ($Lite -or $script:Edition -eq 'Lite') {
    Write-Host ""
    Write-Step "LITE mode - free edition"
    Write-Host ("  Sites scanned                 : {0}" -f $R.SiteCount)
    Write-Host ("  Sites open to every employee  : {0} of {1}" -f $R.EeeuSites.Count, $R.NonOneDriveCount)
    Write-Host ("  Anyone links                  : {0}  ({1} never expire)" -f $R.Anyone.Count, $R.AnyoneNoExpiry)
    Write-Host ("  Guests with site access       : {0}" -f $R.DistinctGuests)
    Write-Host ""
    Write-Host "  Solo/Pro add the HTML report — sharescout.dev" -ForegroundColor Yellow
    Write-Host ""
    Write-Step "CSVs saved to: $OutputPath"
    return
}

