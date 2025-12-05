###############################################################################
# Script originally by others, modified by Kris Springer, Bonomani
# https://www.krisspringer.com
# https://www.ionetworkadmin.com
# Version 0.5 / 2025-12-04 - Compliance check with default "Download" if omitted
###############################################################################
<#
.SYNOPSIS
   Reports Windows Updates and compliance.

.DESCRIPTION
   Checks registry values for Windows Update against simplified SCONFIG profiles
   (Disabled, Manual, Notify, Download).
   - If -CheckSConfig is omitted → validate against default "Download".
   - If -CheckSConfig is provided → validate against that explicit profile.

.EXAMPLE
   Check compliance against default "Download" profile:
   powershell.exe -executionpolicy remotesigned -file "{script}"

.EXAMPLE
   Check compliance against explicit profile:
   powershell.exe -executionpolicy remotesigned -file "{script}" -CheckSConfig Manual

.PARAMETER AUOptions
   Automatic Update behavior (normally absent unless configured):
   - 1: Manual
   - 2: Notify before download
   - 3: Download, notify before install (default)

.PARAMETER NoAutoUpdate
   0 or absent: Enabled (Default)
   1: Disabled

.PARAMETER CheckSConfig
   If omitted → Use "Download".
   If provided → Validate against this profile (Disabled, Manual, Notify, Download).

.PARAMETER Version
   Shows script version.
#>

[CmdletBinding()]
param(
    [ValidateSet("Disabled","Manual","Notify","Download","AutoAdmin")]
    [string]$CheckSConfig,

    [string]$AUOptions,
    [string]$NoAutoUpdate,

    [switch]$Version
)

# Define Constants
$CriticalLimit = 14              # Delay critical updates alarm for days
$ModerateLimit = $CriticalLimit  # Delay moderate updates alarm for days
$OtherLimit = 2 * $ModerateLimit # Delay other updates alarm for days

# Define File Paths
$logFile = 'c:\Program Files\xymon\ext\updates.log'
$cachefile = 'c:\Program Files\xymon\ext\updates.cache.json'
$outputFile = 'c:\Program Files\xymon\tmp\updates'

# Other Settings
$SearchRetries = 0               # Windows update Timeout = 10min, Max time  =  ($SearchRetries + 1 ) * timeout
$debug = $false                  # Write to logfile
$DateFormatYMDHMSF = 'yyyy-MM-dd HH:mm:ss:fff'
$DateFormatYMDHMS = 'yyyy-MM-dd HH:mm:ss'
$DateFormatHMSF = 'HH:mm:ss:fff'

# Function to write debug logs
function Write-DebugLog {
    param(
        [string]$message,
        [string]$filepath = $logFile
    )
    if ($debug) {
        $datestamp = Get-Date -Format $DateFormatYMDHMSF
        Add-Content -Path $filepath -Value "$datestamp  $message"
    }
}

# Main script starts here
$StartTime = Get-Date
Write-DebugLog "Starting"
$ScriptVersion = 0.5

function Test-RegistryValue {
  param(
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()] $Path,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()] $Value
  )
  try {
    Get-ItemProperty -Path $Path -Name $Value -EA Stop
    return $true
  } catch {
    return $false
  }
}

function Test-PendingReboot {
  [bool]$PendingReboot = $false
  $RebootReasons = @()

  if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") {
    $RebootReasons += "Windows Update requires reboot"
    $PendingReboot = $true
  }
  if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\PostRebootReporting") {
    $RebootReasons += "Windows Update PostRebootReporting key exists"
    $PendingReboot = $true
  }
  if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
    $RebootReasons += "CBS servicing reports RebootPending"
    $PendingReboot = $true
  }
  if (Test-Path "HKLM:\SOFTWARE\Microsoft\ServerManager\CurrentRebootAttempts") {
    $RebootReasons += "Server Manager has pending reboot attempts"
    $PendingReboot = $true
  }
  if (Test-RegistryValue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing" -Value "RebootInProgress") {
    $RebootReasons += "CBS reports RebootInProgress"
    $PendingReboot = $true
  }
  if (Test-RegistryValue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing" -Value "PackagesPending") {
    $RebootReasons += "CBS has PackagesPending"
    $PendingReboot = $true
  }
  if (Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Value "PendingFileRenameOperations") {
    $RebootReasons += "PendingFileRenameOperations exist"
    $PendingReboot = $true
  }
  if (Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Value "PendingFileRenameOperations2") {
    $RebootReasons += "PendingFileRenameOperations2 exist"
    $PendingReboot = $true
  }
  if (Test-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -Value "DVDRebootSignal") {
    $RebootReasons += "RunOnce DVDRebootSignal exists"
    $PendingReboot = $true
  }
  if (Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon" -Value "JoinDomain") {
    $RebootReasons += "Netlogon join domain requires reboot"
    $PendingReboot = $true
  }
  if (Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon" -Value "AvoidSpnSet") {
    $RebootReasons += "Netlogon AvoidSpnSet requires reboot"
    $PendingReboot = $true
  }
  try {
    $util = [wmiclass]"\\.\root\ccm\clientsdk:CCM_ClientUtilities"
    $status = $util.DetermineIfRebootPending()
    if (($status -ne $null) -and $status.RebootPending) {
      $RebootReasons += "ConfigMgr reports pending reboot"
      $PendingReboot = $true
    }
  } catch {}

  return [pscustomobject]@{
    Pending = $PendingReboot
    Reasons = $RebootReasons
  }
}

## This section controls the reporting colors.
function Set-Colour
{
  param([string]$currentColour,[string]$newColour)
  if ($currentColour -eq "red") {
    "red"
    # "green"
  } elseif ($newColour -eq "red") {
    "red"
    # "green"
  } elseif ($newColour -eq "yellow") {
    "yellow"
    # "green"
  } else {
    "green"
  }
}

function Get-UpdateSeverity {
    param(
        [Parameter(Mandatory=$true)]
        $Update
    )

    $cats = @($Update.Categories)

    if ($cats -contains "Critical Updates") {
        return "Critical"
    }
    elseif ($cats -contains "Security Updates" -or
            $cats -contains "Definition Updates" -or
            $cats -contains "Windows Security Platform" -or
            $cats -contains "Security Intelligence Update" -or
            $cats -contains "Windows Defender Antivirus" -or
            $cats -contains "Antimalware Client") {
        return "Moderate"
    }
    else {
        return "Other"
    }
}

if ($Version) {
  Write-Host $ScriptVersion
  exit
}

$dateCriticalLimit = (Get-Date).adddays(- $CriticalLimit)
$dateModerateLimit = (Get-Date).adddays(- $ModerateLimit)
$dateOtherLimit = (Get-Date).adddays(- $OtherLimit)
$Computername = $env:COMPUTERNAME
$os = Get-WmiObject Win32_OperatingSystem
$osVersion = $os.version
if (([version]$osVersion).Major -eq "10") { $osVersion = "$(([version]$osVersion).Major).$(([version]$osVersion).Minor).*" }
$osversionLookup = @{ "5.1.2600" = "XP"; "5.1.3790" = "2003"; "6.0.6001" = "Vista/2008"; "6.1.7600" = "Win7/2008R2"; "6.1.7601" = "Win7 SP1/2008R2 SP1"; "6.2.9200" = "Win8/2012"; "6.3.9600" = "Win8.1/2012R2"; "10.0.*" = "Windows 10/Server 2016" };

Write-DebugLog "Searching for PendingReboot"
#$PendingReboot = Test-PendingReboot
$result = Test-PendingReboot
$PendingReboot = $result.Pending

Write-DebugLog "Searching for Windows Update registry compliance"

# ==============================
# Helper: Detect SCONFIG name
# ==============================
function Get-SconfigName {
    param($AUOptions, $NoAutoUpdate)

    if ($NoAutoUpdate -eq 1) {
        return "Disabled"
    }

    switch ($AUOptions) {
        1     { return "Manual" }
        2     { return "Notify" }
        3     { return "Download" }
        4     { return "Automatic" }
        7     { return "AutoAdmin" }
        $null { return "Download" } # default if AUOptions missing
    }
    return $null
}

# ==============================
# Compliance Check
# ==============================
$regPathAU = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
$regAU     = Get-ItemProperty -Path $regPathAU -ErrorAction SilentlyContinue

# Raw values from registry
$rawAUOptions = if ($null -ne $regAU) { $regAU.AUOptions } else { $null }
$rawNAU       = if ($null -ne $regAU) { $regAU.NoAutoUpdate } else { $null }

# Normalize registry values
# - AUOptions absent → default to 3 (Download)
# - NoAutoUpdate absent → default to 0 (Enabled)
$regValueAUOptions = if ($null -ne $rawAUOptions) { $rawAUOptions } else { 3 }
$regValueNAU       = if ($null -ne $rawNAU)       { $rawNAU }       else { 0 }

# Current profile name
$currentName = Get-SconfigName $rawAUOptions $rawNAU

# Expected profile (default = Download, or user override with -CheckSConfig)
$expectedProfile = if ($PSBoundParameters.ContainsKey("CheckSConfig")) { $CheckSConfig } else { "Download" }

# Compliance check
$compliant = ($currentName -eq $expectedProfile)

# One clean summary line with color
if ($compliant) {
    $compliantOutputText = "&green Compliance SCONFIG: expected=$expectedProfile, detected=$currentName, compliant=True`r`n"
} else {
    $compliantOutputText = "&red Compliance SCONFIG: expected=$expectedProfile, detected=$currentName, compliant=False`r`n"
}

# Build expected values
$expectedProfiles = @{
    # Disabled ignores AUOptions → accept any (null,1,2,3,4,7)
    "Disabled"  = @{ AUOptions=@($null,1,2,3,4,7); NoAutoUpdate=1 }
    "Manual"    = @{ AUOptions=1; NoAutoUpdate=0 }
    "Notify"    = @{ AUOptions=2; NoAutoUpdate=0 }
    "Download"  = @{ AUOptions=3; NoAutoUpdate=0 }
    "Automatic" = @{ AUOptions=4; NoAutoUpdate=0 }
    "AutoAdmin" = @{ AUOptions=7; NoAutoUpdate=0 }
}

$exp = $expectedProfiles[$expectedProfile]

function Format-Value {
    param($name, $current, $expected)
    if ($expected -is [array]) { $expectedText = ($expected -join "|") } else { $expectedText = $expected }
    $match = ($expected -is [array] -and $expected -contains $current) -or ($expected -eq $current)
    $color = if ($match) { "&green" } else { "&red" }
    return $color+" "+$name+": "+$current+"/"+$expectedText
}

$compliantOutputText += "   Regs: " + (
    (Format-Value "AUOptions"    $regValueAUOptions $exp.AUOptions),
    (Format-Value "NoAutoUpdate" $regValueNAU       $exp.NoAutoUpdate)
) -join ", "
$compliantOutputText += "`r`n"

# Final compliance flag
$compliantWinUpdateReg = $compliant
# Use a cache to not bloat the system
$cacheIsInvalid = $true
$ParentProcessId = (Tasklist /svc /fi "SERVICES eq XymonPSClient" /fo csv | ConvertFrom-Csv).PID
$LastSearchSuccessDate = (New-Object -com "Microsoft.Update.AutoUpdate").Results.LastSearchSuccessDate

# Récupérer le service par défaut une seule fois
$DefaultAUService = (New-Object -ComObject "Microsoft.Update.ServiceManager").Services |
    Where-Object { $_.IsDefaultAUService } |
    Select-Object ServiceID, Name

if (Test-Path -Path $cachefile -PathType Leaf) {
  Write-DebugLog "Process cache reading "
  $scanCache = Get-Content $cachefile | ConvertFrom-Json

  # Check Args
  $ReferenceObject = $scanCache.Args
  $DifferenceObject = $PsBoundParameters | ConvertTo-Json | ConvertFrom-Json
  [array]$objprops = $ReferenceObject | Get-Member -MemberType Property,NoteProperty | ForEach-Object Name
  $objprops += $DifferenceObject | Get-Member -MemberType Property,NoteProperty | ForEach-Object Name
  $objprops = $objprops | Sort-Object | Select-Object -Unique
  $diffs = @()
  foreach ($objprop in $objprops) {
    $diff = Compare-Object -ReferenceObject $ReferenceObject -DifferenceObject $DifferenceObject -Property $objprop
    if ($diff) {
      $diffprops = @{
        PropertyName = $objprop
        RefValue = ($diff | Where-Object { $_.SideIndicator -eq '<=' } | ForEach-Object $($objprop))
        DiffValue = ($diff | Where-Object { $_.SideIndicator -eq '=>' } | ForEach-Object $($objprop))
      }
      $diffs += New-Object -TypeName PSObject -Property $diffprops
    }
  }
  if ($diffs) {
    foreach ($diff in $diffs) {
      Write-DebugLog ($diff | ForEach-Object { "Cache invalidated by args change key:$($_.PropertyName) val:$($_.DiffValue) cacheVal:$($_.RefValue)" })
    }
    $cacheIsInvalid = $true
  } elseif ($scanCache.ParentProcessId -ne $ParentProcessId) {
    Write-DebugLog "Cache invalidated by parent process changes $PID.Parent.Id"
    $cacheIsInvalid = $true
  } elseif ($scanCache.date -lt (New-Object -com "Microsoft.Update.AutoUpdate").Results.LastSearchSuccessDate) {
    Write-DebugLog "Cache invalidated by Windows update changes"
    $cacheIsInvalid = $true
  } elseif ($scanCache.date.AddHours(11) -lt $StartTime) {
    Write-DebugLog "Cache date too old $($scanCache.date) (max 11 h) "
    $cacheIsInvalid = $true
  } else {
    $cacheIsInvalid = $false
  }
}

if ($cacheIsInvalid) {
  Write-DebugLog "Creating update session"
  $updatesession = [activator]::CreateInstance([type]::GetTypeFromProgID("Microsoft.Update.Session",$Computername))
  Write-DebugLog "Creating update searcher"
  $UpdateSearcher = $updatesession.CreateUpdateSearcher()
  Write-DebugLog "Searching for updates"

  if (((Get-WmiObject Win32_OperatingSystem).Name) -notlike "*Windows 7*") {
    if ($DefaultAUService.ServiceID -eq '7971f918-a847-4430-9279-4a52d1efe18d') {
      $UpdateSearcher.ServiceID = '7971f918-a847-4430-9279-4a52d1efe18d'
      $UpdateSearcher.SearchScope = 1
      $UpdateSearcher.ServerSelection = 3
    } elseif ($DefaultAUService.ServiceID -eq '9482f4b4-e343-43b6-b170-9a65bc822c77') {
      $UpdateSearcher.ServiceID = '9482f4b4-e343-43b6-b170-9a65bc822c77'
    } else {
      exit
    }
  }

  $SearchOnlineSuccess = $false
  $SearchCount = 0

  do {
    try {
      $Criteria = "IsInstalled=0 and DeploymentAction=* or IsPresent=1 and DeploymentAction='Uninstallation' or IsInstalled=1 and DeploymentAction='Installation' and RebootRequired=1 or IsInstalled=0 and DeploymentAction='Uninstallation' and RebootRequired=1"
      $searchresult = $updatesearcher.Search($Criteria)
      $SearchOnlineSuccess = $true
    } catch {}
    $SearchCount++
  } until ($SearchOnlineSuccess -or ($SearchCount -eq ($SearchRetries + 1)))

  if ($SearchOnlineSuccess) {
    $SearchOnlineSuccessDate = $StartTime
  }

  $Updates = if ($searchresult.Updates.Count -gt 0) {
    $count = $searchresult.Updates.Count
    Write-DebugLog "$count updates have been found"
    Write-DebugLog "Looping through updates to retrieve information"
    for ($i = 0; $i -lt $Count; $i++) {
      $Update = $searchresult.Updates.Item($i)
      [pscustomobject]@{
        Title = $Update.Title
        KB = $($Update.KBArticleIDs)
        Severity = Get-UpdateSeverity -Update $Update
        IsBeta = $Update.IsBeta
        IsDownloaded = $Update.IsDownloaded
        IsHidden = $Update.IsHidden
        IsInstalled = $Update.IsInstalled
        IsMandatory = $Update.IsMandatory
        IsPresent = $Update.IsPresent
        RebootRequired = $Update.RebootRequired
        IsUninstallable = $Update.IsUninstallable
        Url = $Update.MoreInfoUrls
        LastDeploymentChangeTime = $Update.LastDeploymentChangeTime
        Categories = ($Update.Categories | Select-Object -ExpandProperty Name)
        BundledUpdates = @($Update.BundledUpdates) | ForEach-Object {
          [pscustomobject]@{
            Title = $_.Title
            DownloadUrl = @($_.DownloadContents).DownloadUrl
          }
        }
      }
    }
  }

  $scan = [pscustomobject]@{
    Args = $PsBoundParameters
    ParentProcessId = $ParentProcessId
    date = $StartTime
    Update = $Updates
    SearchOnlineSuccess = $SearchOnlineSuccess
    SearchOnlineSuccessDate = $SearchOnlineSuccessDate
  }

  ConvertTo-Json -Depth 4 -InputObject $scan | Out-File $cachefile
} else {
  Write-DebugLog "Cache Valid: skipping Windows Update Search"

  [array]$Updates = $scanCache.Update
  $count = $Updates.Count
  if ($count -eq 1) {
    if ("" -eq $Updates[0]) {
      $count=0
    }
  }
  $SearchOnlineSuccess = $scanCache.SearchOnlineSuccess
  if ($SearchOnlineSuccess) {
    [datetime]$SearchOnlineSuccessDate = $scanCache.SearchOnlineSuccessDate
  }
}

$RunTime = New-TimeSpan -Start $StartTime -End (Get-Date)
if ($count -gt 0) {
  Write-DebugLog "Start assembling output"

  # Init counters and outputs
  $criticalCount = 0; $criticalOverdue = 0; $criticalRecent = 0; $criticalOutput = ""
  $moderateCount = 0; $moderateOverdue = 0; $moderateRecent = 0; $moderateOutput = ""
  $otherCount = 0; $otherOverdue = 0; $otherRecent = 0; $otherOutput = ""
  $colour = "green"

  foreach ($wUpdate in $Updates) {
    $severity  = Get-UpdateSeverity -Update $wUpdate
    $patchDate = $wUpdate.LastDeploymentChangeTime
    $patchAge  = (New-TimeSpan -Start $patchDate -End (Get-Date)).Days
    $kb        = $wUpdate.KB
    $title     = $wUpdate.Title
    $isHidden  = $wUpdate.IsHidden

    # Build status flags
    $Status  = ""
    if ($wUpdate.IsBeta) { $Status += "B" } else { $status += "-" }
    if ($wUpdate.IsDownloaded) { $Status += "D" } else { $status += "-" }
    if ($wUpdate.IsHidden) { $Status += "H" } else { $status += "-" }
    if ($wUpdate.IsInstalled) { $Status += "I" } else { $status += "-" }
    if ($wUpdate.IsMandatory) { $Status += "M" } else { $status += "-" }
    if ($wUpdate.IsPresent) { $Status += "P" } else { $status += "-" }
    if ($wUpdate.RebootRequired) { $Status += "R" } else { $status += "-" }
    if ($wUpdate.IsUninstallable) { $Status += "U" } else { $status += "-" }

    # Classify
    if ($severity -eq "Critical" -and -not $isHidden) {
      $criticalCount++
      if ($patchDate -lt $dateCriticalLimit) {
        $criticalOverdue++
        $colour = Set-Colour $colour "red"
      } else {
        $criticalRecent++
        $colour = Set-Colour $colour "yellow"
      }
      $criticalOutput += "<tr><td>$Severity</td><td>$patchAge</td><td><a href=`"https://support.microsoft.com/en-us/kb/$KB`" onclick=`"window.open(this.href); return false;`">$KB</a></td><td>$Status</td><td>$Title</td></tr>`r`n"

    } elseif (($severity -eq "Moderate" -or $severity -eq "Important") -and -not $isHidden) {
      $moderateCount++
      if ($patchDate -lt $dateModerateLimit) {
        $moderateOverdue++
        $colour = Set-Colour $colour "yellow"
      } else {
        $moderateRecent++
        $colour = Set-Colour $colour "green"
      }
      $moderateOutput += "<tr><td>$Severity</td><td>$patchAge</td><td><a href=`"https://support.microsoft.com/en-us/kb/$KB`" onclick=`"window.open(this.href); return false;`"$KB</a></td><td>$Status</td><td>$Title</td></tr>`r`n"

    } else {
      $otherCount++
      if ($patchDate -lt $dateOtherLimit) {
        $otherOverdue++
        $colour = Set-Colour $colour "yellow"
      } else {
        $otherRecent++
        $colour = Set-Colour $colour "green"
      }
      $otherOutput += "<tr><td>Other</td><td>$patchAge</td><td><a href=`"https://support.microsoft.com/en-us/kb/$KB`" onclick=`"window.open(this.href); return false;`">$KB</a></td><td>$Status</td><td>$Title</td></tr>`r`n"
    }
  }

  if ($criticalCount -eq 0) {
    Write-DebugLog "No critical updates"
  }
}
else {
  Write-DebugLog "No updates found"
  $colour = "green"
}

if ($PendingReboot -or -not $SearchOnlineSuccess -or -not $compliantWinUpdateReg) {
  $colour = Set-Colour $colour "yellow"
}

Write-DebugLog "Get hostname"
$fqdnHostname = [System.Net.DNS]::GetHostByName('').HostName.ToLower()
$outputText = $outputText + "$colour+12h {0:$DateFormatYMDHMS}`r`n" -f $StartTime
$outputText = $outputText + "<h2>Windows Updates Check</h2>`r`n"
$outputText += "Critical thresholds: Critical Overdue: $CriticalLimit [days]`r`n"
$outputText += "Warning thresholds:  Critical: 0 [days], Moderate Overdue: $ModerateLimit [days], Other Overdue: $OtherLimit [days]`r`n"

if ($null -ne $DefaultAUService) {
    switch ($DefaultAUService.ServiceID.ToLower()) {
        '7971f918-a847-4430-9279-4a52d1efe18d' {
            $outputText += "Update service: Microsoft Update`r`n"
        }
        '9482f4b4-e343-43b6-b170-9a65bc822c77' {
            $outputText += "Update service: Windows Update (&yellow Expected Microsoft Update)`r`n"
        }
        default {
            $outputText += "Update service: $($DefaultAUService.Name) (ServiceID: $($DefaultAUService.ServiceID))`r`n"
        }
    }
}
else {
    $outputText += "&red Unable to detect default update service`r`n"
}

$outputText = $outputText + "Updates searching time: {0:$DateFormatHMSF}`r`n" -f [datetime]$RunTime.ToString()
$outputText = $outputText + "Last successfull self search: {0:$DateFormatYMDHMS}`r`n" -f $LastSearchSuccessDate
$outputText = $outputText + "Last successfull monitoring search: {0:$DateFormatYMDHMS}`r`n" -f $SearchOnlineSuccessDate

$outputText = $outputText + $compliantOutputText

if (-not $SearchOnlineSuccess) {
  $outputText = $outputText + "&yellow Update is unreachable after retries: $SearchRetries`r`n"
}

# --- Summary output ---
$totalUpdates = $criticalCount + $moderateCount + $otherCount

if ($totalUpdates -gt 0) {
    # Determine overall colour based on worst severity
    if ($criticalOverdue -gt 0) {
        $overallColour = "red"
    }
    elseif ($criticalCount -gt 0 -or $moderateOverdue -gt 0 -or $otherOverdue -gt 0) {
        $overallColour = "yellow"
    }
    else {
        $overallColour = "green"
    }

    $outputText += "&$overallColour Total update(s) available: $totalUpdates`r`n"

    if ($criticalCount -gt 0) {
        if ($criticalOverdue -gt 0) {
            $outputText += "  &red Critical: $criticalCount ($criticalOverdue overdue, $criticalRecent recent)`r`n"
        }
        else {
            $outputText += "  &yellow Critical: $criticalCount ($criticalOverdue overdue, $criticalRecent recent)`r`n"
        }
    }

    if ($moderateCount -gt 0) {
        if ($moderateOverdue -gt 0) {
            $outputText += "  &yellow Moderate/Important: $moderateCount ($moderateOverdue overdue, $moderateRecent recent)`r`n"
        }
        else {
            $outputText += "  &green Moderate/Important: $moderateCount ($moderateOverdue overdue, $moderateRecent recent)`r`n"
        }
    }

    if ($otherCount -gt 0) {
        if ($otherOverdue -gt 0) {
            $outputText += "  &yellow Other: $otherCount ($otherOverdue overdue, $otherRecent recent)`r`n"
        }
        else {
            $outputText += "  &green Other: $otherCount ($otherOverdue overdue, $otherRecent recent)`r`n"
        }
    }
}
else {
    $outputText += "&green Total update(s) available: 0`r`n"
}

if ($PendingReboot) {
  $reasonsText = ($result.Reasons -join ", ")
  $outputText += "&yellow Reboot pending: $reasonsText`r`n"
}

if ($count -gt 0) {
  Write-DebugLog "Updates have been detected so output contains updates listing"
  $outputText = $outputText + "<p>&nbsp;</p>`r`n"
  $outputText = $outputText + "<style>table.updates, table.updates th, table.updates td {border: 1px solid silver; border-collapse:collapse; padding:5px; background-color:black;}</style>`r`n"
  $outputText = $outputText + "<table class=`"updates`"><tr><th>Severity</th><th>Age (days)</th><th>KB</th><th>Status</th><th>Title</th></tr>`r`n"
  $outputText = $outputText + $criticalOutput
  $outputText = $outputText + $moderateOutput
  $outputText = $outputText + $otherOutput
  $outputText = $outputText + "</table>`r`n"
  $outputText = $outputText + "Status=IsBeta,IsDownloaded,IsHidden,IsInstalled,IsMandatory,IsPresent,RebootRequired,IsUninstallable"
}

Write-DebugLog "Save contents into tmp file"
$outputText | Set-Content -Encoding UTF8 $outputFile
