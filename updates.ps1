###############################################################################
# Script originally by others, modified by Kris Springer, Bonomani
# https://www.krisspringer.com
# https://www.ionetworkadmin.com
# Version 1.16 / 2026-05-15 - Convert the file to pure ASCII: an em-dash inside a Write-DebugLog string (v1.13) included a byte that maps to a closing curly quote in cp1252, terminating the string early when PowerShell 5.1 reads the BOM-less file in the system codepage and producing a cascade of fake "ampersand not allowed" errors on every &color literal that follows; replace em-dashes with hyphens, arrows with ->, and the lone French comment with English
# Version 1.15 / 2026-05-15 - Restore PowerShell 2.0 parser compatibility: rewrite the v1.13 "$unknownId = if (...) {} else {}" and v1.14 "$os = try {} catch {}" expression-assignment patterns as plain if/try statements; the inline form was introduced in PowerShell 3.0 and made the parser cascade through every subsequent &color literal as an ampersand error
# Version 1.14 / 2026-05-15 - Factor OS detection at the top of the script with a CIM-first / WMI-fallback pattern (works on stock Win 7 SP1 with WMF 2.0 as well as modern Windows), drop the last raw Get-WmiObject call, document why Windows 7 skips the AU ServiceID overrides
# Version 1.13 / 2026-05-15 - Polish: $ScriptVersion declared as string to avoid PowerShell double-precision stripping trailing zero (e.g. 1.10 displayed as 1.1); log WUA Search() failures in retry loop instead of swallowing silently; emit a red Xymon line and clean lock release before exit when neither Microsoft Update nor Windows Update is the default AU service
# Version 1.12 / 2026-05-15 - Hygiene cleanup: remove unused $os/$osVersion/$osversionLookup and $fqdnHostname, join KBArticleIDs arrays with comma in the report, modernize KB support URLs to /help/ form, document MsrcSeverity unspecified/null fallthrough in Get-UpdateSeverity
# Version 1.11 / 2026-05-15 - Cache hardening: read wrapped in try/catch (corrupt JSON no longer crashes script), atomic write via tmp+Move-Item, drop overly aggressive ParentProcessId invalidation trigger, raise JSON depth from 4 to 10 (BundledUpdates safety), read with Get-Content -Raw (faster), TTL check first in invalidation order (short-circuit on cold cache)
# Version 1.10 / 2026-05-15 - Hidden updates downgrade severity by one level (Critical->Important, Important->Moderate, Moderate->Other) so they stay visible (H flag) but never escalate to red; fixes the prior bug where hidden Critical/Important/Moderate silently fell into the Other bucket via the missing -not isHidden filter
# Version 1.9 / 2026-05-15 - Severity classification refactor: 4 buckets (Critical/Important/Moderate/Other) driven by MsrcSeverity with Security Updates fallback to Important; -CriticalityLevel lever (Low/Standard/High) with per-bucket threshold profiles and granular CLI overrides; cache stores MsrcSeverity; report header shows criticality level and all thresholds
# Version 1.8 / 2026-05-15 - Sync $ScriptVersion with header; emit n/a for "Last probe online scan" when no successful online scan recorded
# Version 1.7 / 2026-05-15 - Fix Set-Colour silently downgrading yellow to green when a non-overdue update was processed after an overdue one
# Version 1.6 / 2026-05-12 - Fix missing ">" in Moderate-row HTML anchor (KB link was unrendered)
# Version 1.5 / 2026-05-12 - Cleaner Regs line: "AUOptions=1 [Manual] (1,2,3,4,7)" style
# Version 1.4 / 2026-05-12 - Skip AU service scan health check in Disabled/Manual modes (no auto scan expected)
# Version 1.3 / 2026-05-12 - Fallback: extract KB from Title when KBArticleIDs is empty
# Version 1.2 / 2026-05-12 - Clearer labels: "Last AU service scan" / "Last probe online scan"
# Version 1.1 / 2026-05-12 - Red when LastSearchSuccessDate is null (API unresponsive), yellow when older than $AutoUpdateMaxAgeDays
# Version 1.0 / 2026-05-12 - Yellow alert when AutoUpdate API unresponsive (LastSearchSuccessDate null)
# Version 0.9 / 2026-05-12 - Bump Invoke-WithTimeout from 15s to 30s
# Version 0.8 / 2026-05-12 - Skip Dispose() on Invoke-WithTimeout timeout path (Dispose blocks on stuck unmanaged thread)
# Version 0.7 / 2026-05-12 - Timeout-guard COM calls to Microsoft.Update.AutoUpdate / ServiceManager (hang on AU-disabled hosts)
# Version 0.6 / 2026-05-12 - Single-instance lock + stale (hung) process cleanup
# Version 0.5 / 2025-12-04 - Compliance check with default "Download" if omitted
###############################################################################
<#
.SYNOPSIS
   Reports Windows Updates and compliance.

.DESCRIPTION
   Checks registry values for Windows Update against simplified SCONFIG profiles
   (Disabled, Manual, Notify, Download).
   - If -CheckSConfig is omitted -> validate against default "Download".
   - If -CheckSConfig is provided -> validate against that explicit profile.

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
   If omitted -> Use "Download".
   If provided -> Validate against this profile (Disabled, Manual, Notify, Download).

.PARAMETER Version
   Shows script version.
#>

[CmdletBinding()]
param(
    [ValidateSet("Disabled","Manual","Notify","Download","AutoAdmin")]
    [string]$CheckSConfig,

    [string]$AUOptions,
    [string]$NoAutoUpdate,

    # Single lever that drives all per-bucket thresholds below.
    # Low = default laxist policy for low-criticality infrastructure.
    [ValidateSet("Low","Standard","High")]
    [string]$CriticalityLevel = "Low",

    # Optional granular overrides - when omitted, values come from the profile.
    [int]$CriticalLimit,
    [int]$ImportantLimit,
    [int]$ModerateLimit,
    [int]$OtherLimit,
    [int]$AutoUpdateMaxAgeDays,

    [switch]$Version
)

# Define Constants
# Threshold profiles per criticality level. Days until an update of that bucket
# turns yellow (or red, for Critical). Profile selection is one source of truth;
# individual params above override per-bucket if explicitly passed.
$criticalityProfiles = @{
    "Low"      = @{ CriticalLimit=14; ImportantLimit=21; ModerateLimit=28; OtherLimit=56; AutoUpdateMaxAgeDays=1 }
    "Standard" = @{ CriticalLimit=7;  ImportantLimit=14; ModerateLimit=21; OtherLimit=28; AutoUpdateMaxAgeDays=1 }
    "High"     = @{ CriticalLimit=3;  ImportantLimit=7;  ModerateLimit=14; OtherLimit=21; AutoUpdateMaxAgeDays=1 }
}

$thresholds = $criticalityProfiles[$CriticalityLevel]
if (-not $PSBoundParameters.ContainsKey('CriticalLimit'))        { $CriticalLimit        = $thresholds.CriticalLimit }
if (-not $PSBoundParameters.ContainsKey('ImportantLimit'))       { $ImportantLimit       = $thresholds.ImportantLimit }
if (-not $PSBoundParameters.ContainsKey('ModerateLimit'))        { $ModerateLimit        = $thresholds.ModerateLimit }
if (-not $PSBoundParameters.ContainsKey('OtherLimit'))           { $OtherLimit           = $thresholds.OtherLimit }
if (-not $PSBoundParameters.ContainsKey('AutoUpdateMaxAgeDays')) { $AutoUpdateMaxAgeDays = $thresholds.AutoUpdateMaxAgeDays }

$MaxRuntimeMinutes = 30          # Hung instances older than this are killed

# Define File Paths
$logFile = 'c:\Program Files\xymon\ext\updates.log'
$cachefile = 'c:\Program Files\xymon\ext\updates.cache.json'
$outputFile = 'c:\Program Files\xymon\tmp\updates'
$lockFile = 'c:\Program Files\xymon\ext\updates.lock'

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

# Run a scriptblock with a hard timeout. Returns $null on timeout or error.
# Guards COM calls that can hang indefinitely:
# - Microsoft.Update.AutoUpdate.Results.* never returns when Automatic Updates
#   is policy-disabled (NoAutoUpdate=1) - observed on Genetec/Server hosts.
# - Microsoft.Update.ServiceManager is in the same family.
# The stuck thread is abandoned but harmless: the script exits shortly after
# writing its output and the OS reclaims it.
function Invoke-WithTimeout {
    param(
        [Parameter(Mandatory=$true)][scriptblock]$ScriptBlock,
        [int]$TimeoutSeconds = 30
    )
    $ps = [PowerShell]::Create()
    [void]$ps.AddScript($ScriptBlock)
    $handle = $ps.BeginInvoke()
    if ($handle.AsyncWaitHandle.WaitOne($TimeoutSeconds * 1000)) {
        # Pipeline finished in time - safe to collect result and dispose.
        try { $result = $ps.EndInvoke($handle) } catch { $result = $null }
        try { $ps.Dispose() } catch {}
        return $result
    }
    # Pipeline still running in unmanaged code (stuck COM call).
    # Do NOT call $ps.Dispose() here: it is synchronous and would block
    # waiting on the same stuck thread we are trying to escape. The
    # runspace and its thread leak until the script process exits a few
    # seconds later - the OS reclaims everything. Acceptable trade-off.
    Write-DebugLog "Invoke-WithTimeout: timed out after $TimeoutSeconds s (runspace abandoned)"
    return $null
}

# Main script starts here
$StartTime = Get-Date
Write-DebugLog "Starting"
$ScriptVersion = '1.16'
$SearchOnlineSuccessDate = $null

# ------------------------------------------------------------------------------
# Single-instance guard.
# Windows Update COM Search() can hang indefinitely (timeout unreliable). Xymon
# relaunches updates.ps1 every scan, so hung instances accumulate. We:
#   1) kill our own previous instances older than $MaxRuntimeMinutes,
#   2) take an exclusive OS file lock on $lockFile; if a fresh instance still
#      holds it, exit immediately so no new powershell.exe piles up.
# The lock handle is released by the OS when the process dies, so a killed
# instance never blocks the next run.
# ------------------------------------------------------------------------------
$myScriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
if ($myScriptPath) {
  $staleThreshold = (Get-Date).AddMinutes(-$MaxRuntimeMinutes)
  try {
    Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction Stop |
      Where-Object {
        $_.ProcessId -ne $PID -and
        $_.CommandLine -and
        $_.CommandLine -like "*$myScriptPath*" -and
        ([Management.ManagementDateTimeConverter]::ToDateTime($_.CreationDate)) -lt $staleThreshold
      } | ForEach-Object {
        Write-DebugLog "Killing stale instance PID $($_.ProcessId) started $($_.CreationDate)"
        try { Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop } catch {
          Write-DebugLog "Failed to kill PID $($_.ProcessId): $_"
        }
      }
  } catch {
    Write-DebugLog "Stale-instance sweep failed: $_"
  }
}

try {
  $script:LockHandle = [System.IO.File]::Open(
    $lockFile,
    [System.IO.FileMode]::Create,
    [System.IO.FileAccess]::ReadWrite,
    [System.IO.FileShare]::None
  )
} catch {
  Write-DebugLog "Another instance holds the lock; exiting"
  exit 0
}

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
  # Preserve worst severity: red > yellow > green.
  # Returning "green" when current is already yellow would silently downgrade.
  param([string]$currentColour,[string]$newColour)
  if ($currentColour -eq "red" -or $newColour -eq "red") {
    "red"
  } elseif ($currentColour -eq "yellow" -or $newColour -eq "yellow") {
    "yellow"
  } else {
    "green"
  }
}

function Get-UpdateSeverity {
    # Returns one of: Critical, Important, Moderate, Other.
    # Primary source: MsrcSeverity (Microsoft Security Response Center verdict).
    # Fallback for updates without an MSRC rating: WSUS category. Per Microsoft
    # documentation, Monthly Rollups are classified as Important on Windows Update,
    # so any Security Updates category entry without explicit MSRC falls into
    # Important (not Moderate) - matches MS intent and surfaces Monthly Rollups.
    param(
        [Parameter(Mandatory=$true)]
        $Update
    )

    # MsrcSeverity can also be $null, "" or "Unspecified" - those fall through
    # the switch and reach the category-based fallback below, which is the
    # correct behavior (no explicit MS verdict -> infer from the WSUS category).
    switch ($Update.MsrcSeverity) {
        "Critical"  { return "Critical" }
        "Important" { return "Important" }
        "Moderate"  { return "Moderate" }
        "Low"       { return "Other" }
    }

    if (@($Update.Categories) -contains "Security Updates") { return "Important" }

    return "Other"
}

if ($Version) {
  Write-Host $ScriptVersion
  exit
}

$dateCriticalLimit  = (Get-Date).adddays(- $CriticalLimit)
$dateImportantLimit = (Get-Date).adddays(- $ImportantLimit)
$dateModerateLimit  = (Get-Date).adddays(- $ModerateLimit)
$dateOtherLimit     = (Get-Date).adddays(- $OtherLimit)
$Computername = $env:COMPUTERNAME

# Detect the OS once with a graceful WMF 2.0 fallback.
# Stock Windows 7 SP1 ships with WMF 2.0, which lacks Get-CimInstance;
# anything from Win 7 SP1 + WMF 3.0 onward (and all server SKUs from 2012+)
# supports CIM and is preferred. The fallback to Get-WmiObject keeps the
# unpatched-Win-7 corner case working.
# NOTE: written as statements (not "$var = try { } catch { }") so the script
# still parses under PowerShell 2.0.
$os = $null
try {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
} catch {
    $os = Get-WmiObject Win32_OperatingSystem
}
$isWindows7 = $os.Name -like "*Windows 7*"

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
# - AUOptions absent -> default to 3 (Download)
# - NoAutoUpdate absent -> default to 0 (Enabled)
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
    # Disabled ignores AUOptions -> accept any (null,1,2,3,4,7)
    "Disabled"  = @{ AUOptions=@($null,1,2,3,4,7); NoAutoUpdate=1 }
    "Manual"    = @{ AUOptions=1; NoAutoUpdate=0 }
    "Notify"    = @{ AUOptions=2; NoAutoUpdate=0 }
    "Download"  = @{ AUOptions=3; NoAutoUpdate=0 }
    "Automatic" = @{ AUOptions=4; NoAutoUpdate=0 }
    "AutoAdmin" = @{ AUOptions=7; NoAutoUpdate=0 }
}

$exp = $expectedProfiles[$expectedProfile]

# Symbolic names per registry key, and the full set of valid values
# (shown as a reference next to the current value). The compliance line
# above already tells the reader what is expected for the active profile.
$auOptionsLookup    = @{ 1='Manual'; 2='Notify'; 3='Download'; 4='Automatic'; 7='AutoAdmin' }
$noAutoUpdateLookup = @{ 0='Enabled'; 1='Disabled' }
$auOptionsPossible    = '1,2,3,4,7'
$noAutoUpdatePossible = '0,1'

function Format-Value {
    param($name, $current, $expected, $symbolLookup, $possibleValues)
    $match  = ($expected -is [array] -and $expected -contains $current) -or ($expected -eq $current)
    $color  = if ($match) { "&green" } else { "&red" }
    $symbol = if ($symbolLookup.ContainsKey([int]$current)) { $symbolLookup[[int]$current] } else { '?' }
    return "$color $name=$current [$symbol] ($possibleValues)"
}

$compliantOutputText += "   Regs: " + (
    (Format-Value "AUOptions"    $regValueAUOptions $exp.AUOptions    $auOptionsLookup    $auOptionsPossible),
    (Format-Value "NoAutoUpdate" $regValueNAU       $exp.NoAutoUpdate $noAutoUpdateLookup $noAutoUpdatePossible)
) -join " "
$compliantOutputText += "`r`n"

# Final compliance flag
$compliantWinUpdateReg = $compliant
# Use a cache to not bloat the system
$cacheIsInvalid = $true

# Wrapped in timeout: Microsoft.Update.AutoUpdate hangs forever when AU is
# disabled by GPO (NoAutoUpdate=1). $null fallback => the script keeps going.
$LastSearchSuccessDate = Invoke-WithTimeout -TimeoutSeconds 30 -ScriptBlock {
    (New-Object -com "Microsoft.Update.AutoUpdate").Results.LastSearchSuccessDate
}

# Fetch the default AU service once (timeout-guarded, same COM family)
$DefaultAUService = Invoke-WithTimeout -TimeoutSeconds 30 -ScriptBlock {
    (New-Object -ComObject "Microsoft.Update.ServiceManager").Services |
        Where-Object { $_.IsDefaultAUService } |
        Select-Object ServiceID, Name
}

# Read cache. A corrupt JSON file (mid-write kill, disk error, manual edit)
# would crash the script if left unguarded; treat any parse failure as an
# invalid cache and fall through to a fresh WUA scan.
$scanCache = $null
if (Test-Path -Path $cachefile -PathType Leaf) {
  Write-DebugLog "Process cache reading "
  try {
    $scanCache = Get-Content -Raw -Path $cachefile | ConvertFrom-Json
  } catch {
    Write-DebugLog "Cache file unreadable or corrupt - discarding: $_"
    $scanCache = $null
  }
}

if ($null -ne $scanCache) {
  # Invalidation triggers, cheapest first so we short-circuit on the common
  # post-TTL cold cache before paying for the args comparison.
  if ($null -eq $scanCache.date -or ([datetime]$scanCache.date).AddHours(11) -lt $StartTime) {
    Write-DebugLog "Cache date too old $($scanCache.date) (max 11 h) "
    $cacheIsInvalid = $true
  } elseif ($null -ne $LastSearchSuccessDate -and [datetime]$scanCache.date -lt [datetime]$LastSearchSuccessDate) {
    Write-DebugLog "Cache invalidated by Windows update changes"
    $cacheIsInvalid = $true
  } else {
    # Args comparison (most expensive, runs only when TTL and AU triggers pass)
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
    } else {
      $cacheIsInvalid = $false
    }
  }
}

if ($cacheIsInvalid) {
  Write-DebugLog "Creating update session"
  $updatesession = [activator]::CreateInstance([type]::GetTypeFromProgID("Microsoft.Update.Session",$Computername))
  Write-DebugLog "Creating update searcher"
  $UpdateSearcher = $updatesession.CreateUpdateSearcher()
  Write-DebugLog "Searching for updates"

  # Windows 7's WUA does not accept explicit ServiceID/SearchScope/ServerSelection
  # overrides - assigning them is a no-op (or throws) there, so skip and let the
  # searcher fall back to the default AU service.
  if (-not $isWindows7) {
    if ($DefaultAUService.ServiceID -eq '7971f918-a847-4430-9279-4a52d1efe18d') {
      $UpdateSearcher.ServiceID = '7971f918-a847-4430-9279-4a52d1efe18d'
      $UpdateSearcher.SearchScope = 1
      $UpdateSearcher.ServerSelection = 3
    } elseif ($DefaultAUService.ServiceID -eq '9482f4b4-e343-43b6-b170-9a65bc822c77') {
      $UpdateSearcher.ServiceID = '9482f4b4-e343-43b6-b170-9a65bc822c77'
    } else {
      # Neither Microsoft Update nor Windows Update is the default AU service.
      # Emit a red Xymon status so the column is not left silently stale, and
      # release the single-instance lock so the next tick can retry cleanly.
      if ($DefaultAUService) { $unknownId = $DefaultAUService.ServiceID } else { $unknownId = 'n/a' }
      Write-DebugLog "Unknown default AU service '$unknownId' - aborting"
      $errOut  = "red+12h {0:$DateFormatYMDHMS}`r`n" -f $StartTime
      $errOut += "<h2>Windows Updates Check</h2>`r`n"
      $errOut += "&red Unable to detect default update service (ServiceID: $unknownId)`r`n"
      $errOut | Set-Content -Encoding UTF8 $outputFile
      try { if ($script:LockHandle) { $script:LockHandle.Close() } } catch {}
      try { Remove-Item $lockFile -Force -ErrorAction SilentlyContinue } catch {}
      exit 1
    }
  }

  $SearchOnlineSuccess = $false
  $SearchCount = 0

  do {
    try {
      $Criteria = "IsInstalled=0 and DeploymentAction=* or IsPresent=1 and DeploymentAction='Uninstallation' or IsInstalled=1 and DeploymentAction='Installation' and RebootRequired=1 or IsInstalled=0 and DeploymentAction='Uninstallation' and RebootRequired=1"
      $searchresult = $updatesearcher.Search($Criteria)
      $SearchOnlineSuccess = $true
    } catch {
      Write-DebugLog "WUA Search() failed (attempt $($SearchCount + 1)): $_"
    }
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
        MsrcSeverity = $Update.MsrcSeverity
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
    date = $StartTime
    Update = $Updates
    SearchOnlineSuccess = $SearchOnlineSuccess
    SearchOnlineSuccessDate = $SearchOnlineSuccessDate
  }

  # Atomic write: emit JSON to a temp file then rename onto the live cache.
  # Move-Item -Force is atomic on the same NTFS filesystem, so a script kill
  # between the write and the rename leaves the previous cache intact.
  $cacheTmpFile = "$cachefile.tmp"
  ConvertTo-Json -Depth 10 -InputObject $scan | Out-File -FilePath $cacheTmpFile
  Move-Item -Path $cacheTmpFile -Destination $cachefile -Force
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
  $criticalCount  = 0; $criticalOverdue  = 0; $criticalRecent  = 0; $criticalOutput  = ""
  $importantCount = 0; $importantOverdue = 0; $importantRecent = 0; $importantOutput = ""
  $moderateCount  = 0; $moderateOverdue  = 0; $moderateRecent  = 0; $moderateOutput  = ""
  $otherCount     = 0; $otherOverdue     = 0; $otherRecent     = 0; $otherOutput     = ""
  $colour = "green"

  foreach ($wUpdate in $Updates) {
    $severity  = Get-UpdateSeverity -Update $wUpdate
    $patchDate = $wUpdate.LastDeploymentChangeTime
    $patchAge  = (New-TimeSpan -Start $patchDate -End (Get-Date)).Days
    # KBArticleIDs can be an array (rare, but happens on rollups bundling
    # multiple KBs); join with comma so the HTML cell stays readable.
    $kb        = (@($wUpdate.KB) | Where-Object { $_ }) -join ', '
    $title     = $wUpdate.Title
    # Microsoft does not always populate KBArticleIDs (.NET cumulatives, etc.).
    # Fall back to parsing "KB#######" from the title to keep the column consistent.
    if ([string]::IsNullOrWhiteSpace("$kb") -and $title -match 'KB(\d+)') {
      $kb = $Matches[1]
    }

    # Hidden = admin explicitly acknowledged this update and asked to ignore it.
    # Downgrade severity by one level so the update stays visible (H flag in the
    # status column) but never escalates to red. Uniform rule across all severities.
    if ($wUpdate.IsHidden) {
      $severity = switch ($severity) {
        "Critical"  { "Important" }
        "Important" { "Moderate" }
        "Moderate"  { "Other" }
        default     { "Other" }
      }
    }

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
    if ($severity -eq "Critical") {
      $criticalCount++
      if ($patchDate -lt $dateCriticalLimit) {
        $criticalOverdue++
        $colour = Set-Colour $colour "red"
      } else {
        $criticalRecent++
        $colour = Set-Colour $colour "yellow"
      }
      $criticalOutput += "<tr><td>$Severity</td><td>$patchAge</td><td><a href=`"https://support.microsoft.com/help/$KB`" onclick=`"window.open(this.href); return false;`">$KB</a></td><td>$Status</td><td>$Title</td></tr>`r`n"

    } elseif ($severity -eq "Important") {
      $importantCount++
      if ($patchDate -lt $dateImportantLimit) {
        $importantOverdue++
        $colour = Set-Colour $colour "yellow"
      } else {
        $importantRecent++
        $colour = Set-Colour $colour "green"
      }
      $importantOutput += "<tr><td>$Severity</td><td>$patchAge</td><td><a href=`"https://support.microsoft.com/help/$KB`" onclick=`"window.open(this.href); return false;`">$KB</a></td><td>$Status</td><td>$Title</td></tr>`r`n"

    } elseif ($severity -eq "Moderate") {
      $moderateCount++
      if ($patchDate -lt $dateModerateLimit) {
        $moderateOverdue++
        $colour = Set-Colour $colour "yellow"
      } else {
        $moderateRecent++
        $colour = Set-Colour $colour "green"
      }
      $moderateOutput += "<tr><td>$Severity</td><td>$patchAge</td><td><a href=`"https://support.microsoft.com/help/$KB`" onclick=`"window.open(this.href); return false;`">$KB</a></td><td>$Status</td><td>$Title</td></tr>`r`n"

    } else {
      $otherCount++
      if ($patchDate -lt $dateOtherLimit) {
        $otherOverdue++
        $colour = Set-Colour $colour "yellow"
      } else {
        $otherRecent++
        $colour = Set-Colour $colour "green"
      }
      $otherOutput += "<tr><td>$Severity</td><td>$patchAge</td><td><a href=`"https://support.microsoft.com/help/$KB`" onclick=`"window.open(this.href); return false;`">$KB</a></td><td>$Status</td><td>$Title</td></tr>`r`n"
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

# In Disabled (NoAutoUpdate=1) and Manual (AUOptions=1) modes, AU does not
# auto-scan by design, so an empty/stale LastSearchSuccessDate is expected
# and must not raise an alert. Only evaluate health when an auto-scan mode
# is configured.
$AutoScanExpected = $currentName -notin @("Disabled", "Manual")

if ($AutoScanExpected) {
  if ($null -eq $LastSearchSuccessDate) {
    $colour = Set-Colour $colour "red"
  } elseif ((New-TimeSpan -Start $LastSearchSuccessDate -End (Get-Date)).TotalDays -gt $AutoUpdateMaxAgeDays) {
    $colour = Set-Colour $colour "yellow"
  }
}

if ($PendingReboot -or -not $SearchOnlineSuccess -or -not $compliantWinUpdateReg) {
  $colour = Set-Colour $colour "yellow"
}

$outputText = $outputText + "$colour+12h {0:$DateFormatYMDHMS}`r`n" -f $StartTime
$outputText = $outputText + "<h2>Windows Updates Check</h2>`r`n"
$outputText += "Criticality level:   $CriticalityLevel`r`n"
$outputText += "Red threshold:       Critical Overdue: $CriticalLimit [days]`r`n"
$outputText += "Yellow thresholds:   Critical: 0 [days], Important Overdue: $ImportantLimit [days], Moderate Overdue: $ModerateLimit [days], Other Overdue: $OtherLimit [days]`r`n"
$outputText += "AU scan max age:     $AutoUpdateMaxAgeDays [days]`r`n"

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
if (-not $AutoScanExpected) {
  if ($null -eq $LastSearchSuccessDate) {
    $outputText += "Last AU service scan: n/a (not evaluated in $currentName mode)`r`n"
  } else {
    $outputText += "Last AU service scan: {0:$DateFormatYMDHMS} (not evaluated in $currentName mode)`r`n" -f $LastSearchSuccessDate
  }
} elseif ($null -eq $LastSearchSuccessDate) {
  $outputText += "&red Last AU service scan: n/a (Automatic Updates API unresponsive or never scanned)`r`n"
} else {
  $selfSearchAgeDays = [math]::Round((New-TimeSpan -Start $LastSearchSuccessDate -End (Get-Date)).TotalDays, 1)
  if ($selfSearchAgeDays -gt $AutoUpdateMaxAgeDays) {
    $outputText += "&yellow Last AU service scan: {0:$DateFormatYMDHMS} (stale: $selfSearchAgeDays days old, threshold $AutoUpdateMaxAgeDays)`r`n" -f $LastSearchSuccessDate
  } else {
    $outputText += "Last AU service scan: {0:$DateFormatYMDHMS}`r`n" -f $LastSearchSuccessDate
  }
}
if ($null -eq $SearchOnlineSuccessDate) {
  $outputText += "&red Last probe online scan: n/a (no successful online scan)`r`n"
} else {
  $outputText += "Last probe online scan: {0:$DateFormatYMDHMS}`r`n" -f $SearchOnlineSuccessDate
}

$outputText = $outputText + $compliantOutputText

if (-not $SearchOnlineSuccess) {
  $outputText = $outputText + "&yellow Update is unreachable after retries: $SearchRetries`r`n"
}

# --- Summary output ---
$totalUpdates = $criticalCount + $importantCount + $moderateCount + $otherCount

if ($totalUpdates -gt 0) {
    # Determine overall colour based on worst severity
    if ($criticalOverdue -gt 0) {
        $overallColour = "red"
    }
    elseif ($criticalCount -gt 0 -or $importantOverdue -gt 0 -or $moderateOverdue -gt 0 -or $otherOverdue -gt 0) {
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

    if ($importantCount -gt 0) {
        if ($importantOverdue -gt 0) {
            $outputText += "  &yellow Important: $importantCount ($importantOverdue overdue, $importantRecent recent)`r`n"
        }
        else {
            $outputText += "  &green Important: $importantCount ($importantOverdue overdue, $importantRecent recent)`r`n"
        }
    }

    if ($moderateCount -gt 0) {
        if ($moderateOverdue -gt 0) {
            $outputText += "  &yellow Moderate: $moderateCount ($moderateOverdue overdue, $moderateRecent recent)`r`n"
        }
        else {
            $outputText += "  &green Moderate: $moderateCount ($moderateOverdue overdue, $moderateRecent recent)`r`n"
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
  $outputText = $outputText + $importantOutput
  $outputText = $outputText + $moderateOutput
  $outputText = $outputText + $otherOutput
  $outputText = $outputText + "</table>`r`n"
  $outputText = $outputText + "Status=IsBeta,IsDownloaded,IsHidden,IsInstalled,IsMandatory,IsPresent,RebootRequired,IsUninstallable"
}

Write-DebugLog "Save contents into tmp file"
$outputText | Set-Content -Encoding UTF8 $outputFile

# Release single-instance lock (handle also auto-released if process is killed)
try { if ($script:LockHandle) { $script:LockHandle.Close() } } catch {}
try { Remove-Item $lockFile -Force -ErrorAction SilentlyContinue } catch {}
