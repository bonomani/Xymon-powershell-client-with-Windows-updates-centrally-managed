#requires -Version 3.0
###############################################################################
# Script originally by others, modified by Kris Springer, Bonomani
# https://www.krisspringer.com
# https://www.ionetworkadmin.com
# Version 1.36 / 2026-05-18 - Rename the AUOptions=7 compliance profile from misleading "AutoAdmin" to "NotifyInstallRestart", matching the real Windows Server behavior (auto-download, notify to install, notify to restart)
# Version 1.35 / 2026-05-18 - Datetime safety net on cache trigger evaluation: wrap the whole if/elseif chain that compares cache.date / cache.LastBootUpTime / AU dates in try/catch, so a cache whose JSON parses but whose timestamp fields are non-parseable (manual edit, partial truncation, future schema drift) is treated as invalid and re-scanned rather than crashing the script - the [datetime] cast was the last unguarded edge that could propagate a fatal exception
# Version 1.34 / 2026-05-18 - Hygiene fixes: move the -Version check ahead of the lock acquisition so it never blocks behind a running scan and never leaves an orphan lock file; format the Searching duration line as a real TimeSpan instead of an awkward [datetime] cast that would have wrapped past 24 h; switch the AU-busy probe to Get-Process -Name <array> instead of piping every running process through Where-Object; normalise the Status-flag append loop to a consistent $Status casing; refresh the Invoke-WithTimeout comment to reflect that kernel-stuck processes can persist long after the function returns
# Version 1.33 / 2026-05-18 - Invalidate the cache and reset FailureRetryCount when the host has rebooted since the cache was written: probe Win32_OperatingSystem.LastBootUpTime at startup, store it in the cache, and add a new invalidation trigger that fires when the current boot time is newer than the cached one; a reboot typically clears the transient state that caused the previous failure chain (stuck COM, locked files, half-finished install), so resuming the retry count at 1 instead of letting the cap silently suppress retries lets the script recover immediately after a boot
# Version 1.32 / 2026-05-18 - Replace the IUpdateInstaller.IsBusy / IUpdateDownloader.IsBusy AU-busy probe with process-level detection of the Update Session Orchestrator workers (MoUsoCoreWorker.exe, USOClient.exe, TiWorker.exe, wuauclt.exe); the COM IsBusy property is a confirmed Microsoft bug on Windows 11 / Server 2022 (always returns false even during active downloads and installs), so the original v1.25 probe was effectively a no-op on modern hosts - process presence is the reliable signal recommended by the WUA community
# Version 1.31 / 2026-05-18 - Raise the stale-instance kill threshold from 30 to 60 minutes so a legitimately slow scan (cold WUA against a slow proxy or a large catalog) is not killed prematurely
# Version 1.30 / 2026-05-18 - Replace lock-only single-instance guard with process-based detection plus escalating kill: every tick enumerates powershell.exe instances whose CommandLine references this script, exits if a young instance is still working, and kills stale ones (>= $MaxRuntimeMinutes old) through Stop-Process -Force -> taskkill /F /T -> WMI Terminate before proceeding; the OS file lock is kept as a race-condition guard but no longer the only line of defence, because Invoke-WithTimeout releases the lock while the orphan COM runspace keeps the process alive as an unkillable-by-default zombie - that scenario was letting ticks pile up new zombies on top of older ones at every Xymon poll
# Version 1.29 / 2026-05-18 - Cross-run retry on a failed cache: cache now stores FailureRetryCount, which increments on every actual WUA Search() failure and resets to 0 on success; when the cache is reused and the previous run failed, the next tick invalidates and retries up to $SearchFailureMaxRetries times (default 5) before giving up and waiting for the TTL or an AU scan/install trigger - that closes the gap where a single transient failure would keep the column stuck on "cached failure from previous run" for the full 11 h TTL window; lock-blocked exits and AU-busy cache reuses leave the counter alone because they don't perform a scan; $SearchAttempts default drops to 1 since the cross-run retry already covers transients
# Version 1.28 / 2026-05-16 - Replace the five per-bucket threshold lines in Configuration with a markdown-style table (|Bucket|Yellow|Red|) - the matrix layout makes the policy easier to read at a glance and stays trivially parseable: any line starting with "|" is a table row, three pipe-separated cells, no state machine needed; values are plain integers with the "(days)" unit pulled into the table caption
# Version 1.27 / 2026-05-16 - Restructure the report body into flat key:value pairs grouped into "--- Configuration ---", "--- Scan ---" and "--- Compliance ---" sections with consistent 26/22-char colon alignment; every line in Configuration and Scan now parses with a single regex "^([^:]+?)\s*:\s*(.+)$", the per-bucket thresholds get a dedicated line each instead of being smashed into one comma-soup line, and a downstream tool can extract any value (or the full config) without knowing the script's internal naming
# Version 1.26 / 2026-05-16 - SCONFIG compliance failure now escalates the Xymon status to red rather than yellow; the operator explicitly opted into the check (either via -CheckSConfig or the implicit "Download" default), so a detected deviation is an intentional policy violation that deserves the same severity as the inline "&red Compliance SCONFIG: ... compliant=False" line - PendingReboot and SearchOnlineSuccess remain at yellow because they are operational signals rather than policy violations
# Version 1.25 / 2026-05-15 - Detect that WUA is already busy with another download or install via Microsoft.Update.Installer.IsBusy + Microsoft.Update.Downloader.IsBusy before launching our own Search(); when the probe says yes and a previous cache is available, reuse it rather than serialise on the wuauserv lock, which was stalling foreground manual installs at 0% during a script run; with no cache to fall back on we still proceed with Search() because reporting nothing is worse than late, and the skip is surfaced in the report on a dedicated line
# Version 1.24 / 2026-05-15 - Wrap WUA Search() and result enumeration in Invoke-WithTimeout so a hung COM call can no longer pin the script past the configured cap (default 10 min), retry up to $SearchAttempts (default 2) with $SearchRetryDelaySeconds (default 30 s) between tries so a transient failure (collision with a concurrent AU agent scan, momentary throttling) doesn't surface as a missed run, and replace the misleading "Update is unreachable after retries: $SearchRetries" line with an actual attempt count plus the last exception message
# Version 1.23 / 2026-05-15 - Initialise the bucket counters unconditionally so they survive the no-cache + Search()-failed path; v1.19 had moved them inside the "if ($count -gt 0)" block, which meant they stayed $null when Windows Update was unreachable and no prior cache existed, causing $criticalCount + ... = $null and an empty "Total update(s) available:" line in the report
# Version 1.22 / 2026-05-15 - Invalidate the cache when an update has been installed since it was written: probe LastInstallationSuccessDate alongside LastSearchSuccessDate (same AutoUpdate.Results call, returned as a hashtable so the values cross the runspace boundary safely) and add a fourth invalidation trigger that fires when an install happened between the cache write and the current run; closes the gap where a manual install was invisible to Xymon until the AU service rescanned or the 11 h TTL expired
# Version 1.21 / 2026-05-15 - PendingFileRenameOperations sources can also carry a "*" or "*<digits>" MoveFileEx flag marker before the "\??\" NT prefix (observed in the wild as *1\??\C:\...); strip it too so the printed list shows the normal Windows path
# Version 1.20 / 2026-05-15 - PendingFileRenameOperations: replace the existence-only check with a real count of source entries, expose a $PendingFileRenameThreshold profile knob (Low=10, Standard=3, High=0) and matching CLI override so harmless legacy entries no longer trip the reboot-pending alarm, and always print the queued source paths in the report so the operator can see exactly what is waiting (\??\ NT prefix stripped for readability)
# Version 1.19 / 2026-05-15 - Consolidate the two parallel colour computations into a single source of truth derived from the bucket counters after the loop; the loop no longer calls Set-Colour per-update (8 calls removed) and the duplicate $overallColour calculation in the Total-line block is gone; $colour is now $overallColour plus the external health modifiers (AU scan, reboot, compliance), so the Total line and the Xymon header stay aligned by construction and adding a future bucket only touches one place
# Version 1.18 / 2026-05-15 - Declare #requires -Version 3.0 so hosts running stock Windows PowerShell 2.0 (Win 7 SP1 without WMF upgrade) get a clean engine-level error instead of cascading parser failures - the script has always implicitly required PS 3.0+ via ConvertFrom-Json, [pscustomobject], and Get-CimInstance, this just makes the requirement explicit
# Version 1.17 / 2026-05-15 - Add UTF-8 BOM to the source file so future edits that re-introduce non-ASCII characters (in any string or comment) no longer risk being misread as cp1252 by Windows PowerShell 5.1; the byte-for-byte behavior is unchanged because the content is already pure ASCII, the BOM is purely defensive against regression
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
   (Disabled, Manual, Notify, Download, Automatic, NotifyInstallRestart).
   - If -CheckSConfig is omitted -> validate against default "Download".
   - If -CheckSConfig is provided -> validate against that explicit profile.

.EXAMPLE
   Check compliance against default "Download" profile:
   powershell.exe -executionpolicy remotesigned -file "{script}"

.EXAMPLE
   Check compliance against explicit profile:
   powershell.exe -executionpolicy remotesigned -file "{script}" -CheckSConfig Manual

.PARAMETER CheckSConfig
   If omitted -> Use "Download".
   If provided -> Validate against this profile
   (Disabled, Manual, Notify, Download, Automatic, NotifyInstallRestart).

.PARAMETER Version
   Shows script version.
#>

[CmdletBinding()]
param(
    [ValidateSet("Disabled","Manual","Notify","Download","Automatic","NotifyInstallRestart")]
    [string]$CheckSConfig,

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
    [int]$PendingFileRenameThreshold,

    [switch]$Version
)

# Define Constants
# Threshold profiles per criticality level. Days until an update of that bucket
# turns yellow (or red, for Critical). Profile selection is one source of truth;
# individual params above override per-bucket if explicitly passed.
# PendingFileRenameThreshold: maximum number of PendingFileRenameOperations
# entries that are tolerated before the script raises a "reboot pending" alarm.
# Windows often carries 1-5 legacy entries that never clear (locked drivers,
# antivirus update artefacts) - on a low-criticality host they are background
# noise rather than an actionable signal.
$criticalityProfiles = @{
    "Low"      = @{ CriticalLimit=14; ImportantLimit=21; ModerateLimit=28; OtherLimit=56; AutoUpdateMaxAgeDays=1; PendingFileRenameThreshold=10 }
    "Standard" = @{ CriticalLimit=7;  ImportantLimit=14; ModerateLimit=21; OtherLimit=28; AutoUpdateMaxAgeDays=1; PendingFileRenameThreshold=3 }
    "High"     = @{ CriticalLimit=3;  ImportantLimit=7;  ModerateLimit=14; OtherLimit=21; AutoUpdateMaxAgeDays=1; PendingFileRenameThreshold=0 }
}

$thresholds = $criticalityProfiles[$CriticalityLevel]
if (-not $PSBoundParameters.ContainsKey('CriticalLimit'))              { $CriticalLimit              = $thresholds.CriticalLimit }
if (-not $PSBoundParameters.ContainsKey('ImportantLimit'))             { $ImportantLimit             = $thresholds.ImportantLimit }
if (-not $PSBoundParameters.ContainsKey('ModerateLimit'))              { $ModerateLimit              = $thresholds.ModerateLimit }
if (-not $PSBoundParameters.ContainsKey('OtherLimit'))                 { $OtherLimit                 = $thresholds.OtherLimit }
if (-not $PSBoundParameters.ContainsKey('AutoUpdateMaxAgeDays'))       { $AutoUpdateMaxAgeDays       = $thresholds.AutoUpdateMaxAgeDays }
if (-not $PSBoundParameters.ContainsKey('PendingFileRenameThreshold')) { $PendingFileRenameThreshold = $thresholds.PendingFileRenameThreshold }

$MaxRuntimeMinutes = 60          # Hung instances older than this are killed

# Define File Paths
$logFile = 'c:\Program Files\xymon\ext\updates.log'
$cachefile = 'c:\Program Files\xymon\ext\updates.cache.json'
$outputFile = 'c:\Program Files\xymon\tmp\updates'
$lockFile = 'c:\Program Files\xymon\ext\updates.lock'

# Other Settings
# $SearchAttempts            : WUA Search() attempts within a single run.
#                              Defaults to 1 because the cross-run retry below
#                              already covers transient failures - additional
#                              in-run attempts would just hold the lock longer.
# $SearchTimeoutSeconds      : per-attempt cap so a hung Search() cannot pin
#                              the run (real cold scans can take 5-10 min).
# $SearchRetryDelaySeconds   : pause between in-run attempts (only used when
#                              $SearchAttempts > 1).
# $SearchFailureMaxRetries   : maximum number of consecutive runs that retry a
#                              failed cache. Counter lives in the cache itself,
#                              increments on every actual scan failure, resets
#                              to 0 on success. Lock-blocked exits and AU-busy
#                              cache reuses do not touch the counter because
#                              they don't perform a scan.
$SearchAttempts            = 1
$SearchTimeoutSeconds      = 600
$SearchRetryDelaySeconds   = 30
$SearchFailureMaxRetries   = 5
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
# - IUpdateSearcher.Search() can hang in kernel mode for hours on a stalled
#   WUA backend (broken proxy, busy AU agent collision).
# The stuck thread is abandoned by this function but the host process itself
# may stay alive for a long time afterward (kernel-stuck syscalls survive
# regular signals). The process-based single-instance guard at the top of the
# script is the one that eventually cleans those zombies up at the next tick.
function Invoke-WithTimeout {
    param(
        [Parameter(Mandatory=$true)][scriptblock]$ScriptBlock,
        [int]$TimeoutSeconds = 30,
        [object[]]$Arguments = @()
    )
    $ps = [PowerShell]::Create()
    [void]$ps.AddScript($ScriptBlock)
    foreach ($a in $Arguments) {
        [void]$ps.AddArgument($a)
    }
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
$ScriptVersion = '1.36'

# -Version is a pure metadata query: handle it before touching the lock or
# enumerating processes, so it never blocks behind a running scan and never
# leaves an orphan lock file behind.
if ($Version) {
  Write-Host $ScriptVersion
  exit
}

$SearchOnlineSuccessDate = $null

# ------------------------------------------------------------------------------
# Single-instance guard.
# Windows Update COM Search() can hang indefinitely in kernel mode. The OS
# file lock alone is not enough because Invoke-WithTimeout abandons the
# stuck COM runspace and the main thread releases the lock at exit - the
# process itself sticks around as a zombie until the kernel call unwinds,
# which can take hours or never. New ticks would then walk past the released
# lock and pile a fresh zombie on top.
#
# So we drive single-instance via *process detection* (every powershell.exe
# whose CommandLine references this script counts as an existing instance):
#
#   - Recent instance (< $MaxRuntimeMinutes old): treat as legitimate active
#     scan and exit so we do not interfere.
#   - Stale instance (>= $MaxRuntimeMinutes old): try to kill it through an
#     escalating chain of methods, then proceed.
#
# The OS file lock is kept as a belt-and-suspenders synchroniser against the
# race where two ticks pass the process scan at the exact same moment.
# ------------------------------------------------------------------------------

function Stop-ScriptInstance {
  # Try to terminate a powershell instance using progressively more aggressive
  # methods. Returns $true if the process is gone afterwards, $false if even
  # the deepest method failed (kernel-stuck thread - only a reboot will fix).
  param([Parameter(Mandatory=$true)][CimInstance]$Process)
  $targetPid = [int]$Process.ProcessId
  $methods = @(
    @{ Name = 'Stop-Process -Force'; Action = {
        Stop-Process -Id $targetPid -Force -ErrorAction Stop
    } },
    @{ Name = 'taskkill /F /T'; Action = {
        $null = & taskkill /F /T /PID $targetPid 2>&1
        if ($LASTEXITCODE -ne 0) { throw "taskkill exit $LASTEXITCODE" }
    } },
    @{ Name = 'WMI Terminate'; Action = {
        $r = Invoke-CimMethod -InputObject $Process -MethodName Terminate -ErrorAction Stop
        if ($r.ReturnValue -ne 0) { throw "WMI Terminate returned $($r.ReturnValue)" }
    } }
  )
  foreach ($m in $methods) {
    try { & $m.Action } catch {
      Write-DebugLog "Kill method '$($m.Name)' on PID $targetPid failed: $_"
      continue
    }
    Start-Sleep -Milliseconds 500
    if (-not (Get-Process -Id $targetPid -ErrorAction SilentlyContinue)) {
      Write-DebugLog "Killed PID $targetPid via '$($m.Name)'"
      return $true
    }
    Write-DebugLog "Kill method '$($m.Name)' on PID $targetPid returned but process still alive"
  }
  Write-DebugLog "PID $targetPid could not be killed (kernel-stuck thread?) - leaving as-is"
  return $false
}

$myScriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
if ($myScriptPath) {
  try {
    $existingInstances = @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction Stop |
      Where-Object {
        $_.ProcessId -ne $PID -and
        $_.CommandLine -and
        $_.CommandLine -like "*$myScriptPath*"
      })
    foreach ($inst in $existingInstances) {
      $instCreated = [Management.ManagementDateTimeConverter]::ToDateTime($inst.CreationDate)
      $instAgeMin  = [math]::Round(((Get-Date) - $instCreated).TotalMinutes, 1)
      if ($instAgeMin -ge $MaxRuntimeMinutes) {
        Write-DebugLog "Stale instance PID $($inst.ProcessId), age $instAgeMin min (>= $MaxRuntimeMinutes) - killing"
        $null = Stop-ScriptInstance -Process $inst
      } else {
        Write-DebugLog "Active instance PID $($inst.ProcessId), age $instAgeMin min (< $MaxRuntimeMinutes) - exiting"
        exit 0
      }
    }
  } catch {
    Write-DebugLog "Existing-instance scan failed: $_"
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

function Get-PendingFileRenameSources {
  # Reads a REG_MULTI_SZ PendingFileRenameOperations[2] value and returns the
  # source paths (even-indexed entries) with their Windows-internal prefixes
  # stripped for readability. Returns @() when the value is absent.
  #
  # Each entry can carry up to two Windows internal prefixes:
  #   - "*" or "*<digits>" - MoveFileEx flag marker (e.g. *1 = a specific flag
  #                          set when the entry was queued)
  #   - "\??\"             - NT object namespace prefix
  # Strip both so the operator sees a normal "C:\path\to\file" path.
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$ValueName
  )
  try {
    $raw = (Get-ItemProperty -Path $Path -Name $ValueName -ErrorAction Stop).$ValueName
  } catch {
    return @()
  }
  if (-not $raw) { return @() }
  $sources = @()
  for ($i = 0; $i -lt $raw.Length; $i += 2) {
    $src = $raw[$i]
    if ($src) {
      $sources += ($src -replace '^\*\d*', '' -replace '^\\\?\?\\', '')
    }
  }
  return $sources
}

function Test-PendingReboot {
  param([int]$PendingFileRenameThreshold = 0)
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

  # PendingFileRenameOperations(2) accumulate over time on Windows: a typical
  # host carries 1-5 legacy entries that never get processed (locked drivers,
  # antivirus updater leftovers). Read the actual list, count the source
  # entries, and only treat the bucket as a reboot reason once the count
  # exceeds the configured threshold; either way, surface the paths via
  # PendingFileRenames so the operator can inspect what is queued.
  $smPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
  $pfr1 = Get-PendingFileRenameSources -Path $smPath -ValueName "PendingFileRenameOperations"
  $pfr2 = Get-PendingFileRenameSources -Path $smPath -ValueName "PendingFileRenameOperations2"
  $pfrTotal = $pfr1.Count + $pfr2.Count
  if ($pfrTotal -gt $PendingFileRenameThreshold) {
    $RebootReasons += "PendingFileRenameOperations: $pfrTotal entries (threshold: $PendingFileRenameThreshold)"
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
    PendingFileRenames = $pfr1 + $pfr2
    PendingFileRenameThreshold = $PendingFileRenameThreshold
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
$result = Test-PendingReboot -PendingFileRenameThreshold $PendingFileRenameThreshold
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
        7     { return "NotifyInstallRestart" }
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

# Expected profile (default = Download, or user override with -CheckSConfig).
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
    "Automatic"            = @{ AUOptions=4; NoAutoUpdate=0 }
    "NotifyInstallRestart" = @{ AUOptions=7; NoAutoUpdate=0 }
}

$exp = $expectedProfiles[$expectedProfile]

# Symbolic names per registry key, and the full set of valid values
# (shown as a reference next to the current value). The compliance line
# above already tells the reader what is expected for the active profile.
$auOptionsLookup    = @{ 1='Manual'; 2='Notify'; 3='Download'; 4='Automatic'; 7='NotifyInstallRestart' }
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
# Probe both LastSearchSuccessDate (used for AU health) and
# LastInstallationSuccessDate (used to invalidate the cache when an update was
# installed between two runs) in the same COM call - the AutoUpdate.Results
# object is the same backing store. Return a hashtable rather than the COM
# object itself so the values cross the runspace boundary safely (Runspace
# marshalling of COM objects is unreliable on some host configurations).
$auState = Invoke-WithTimeout -TimeoutSeconds 30 -ScriptBlock {
    $auResults = (New-Object -com "Microsoft.Update.AutoUpdate").Results
    @{
        Search  = $auResults.LastSearchSuccessDate
        Install = $auResults.LastInstallationSuccessDate
    }
}
if ($auState) {
    $LastSearchSuccessDate       = $auState.Search
    $LastInstallationSuccessDate = $auState.Install
} else {
    $LastSearchSuccessDate       = $null
    $LastInstallationSuccessDate = $null
}

# Fetch the default AU service once (timeout-guarded, same COM family)
$DefaultAUService = Invoke-WithTimeout -TimeoutSeconds 30 -ScriptBlock {
    (New-Object -ComObject "Microsoft.Update.ServiceManager").Services |
        Where-Object { $_.IsDefaultAUService } |
        Select-Object ServiceID, Name
}

# Probe the system boot time so the cache layer can detect a reboot since the
# last cache write. A reboot typically clears the conditions that caused the
# previous failures (stuck COM call, locked file, half-finished install), so
# when we see one we invalidate the cache AND reset the FailureRetryCount so
# the cap does not silently suppress retries that would have succeeded now.
try {
    $currentBootTime = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime
} catch {
    $currentBootTime = $null
}
$rebootClearedFailures = $false

# Probe whether WUA is currently doing a scan, download or install in another
# session (manual GUI install, AU agent scheduled scan, configmgr push, etc.).
# Our own Search() would serialise on the wuauserv lock and stall - or stall
# the foreground operation - so when the probe says yes we prefer to reuse the
# existing cache rather than fight for the lock.
#
# We can't ask the WUA API directly: IUpdateInstaller.IsBusy is broken on
# Windows 11 and Windows Server 2022 (always returns false even when an
# install is actively running - confirmed Microsoft bug), and IUpdateSearcher
# exposes no IsBusy property at all. The reliable signal is process-level:
# the Update Session Orchestrator spawns specific worker processes whenever
# it is doing work, and they linger only for a minute or two after.
#   - MoUsoCoreWorker.exe : USO core worker (scan/download/install)
#   - USOClient.exe       : USO trigger (transient, spawns MoUsoCoreWorker)
#   - TiWorker.exe        : Windows Modules Installer worker (install phase)
#   - wuauclt.exe         : legacy WU client (mostly Win 7/8 era)
# Presence of any of these is treated as "WUA is busy".
$auBusy = $null
try {
    $busyMarkers = @('TiWorker','MoUsoCoreWorker','USOClient','wuauclt')
    # Get-Process -Name accepts an array and short-circuits on names that do
    # not exist (returns matching ones, ignores misses with -ErrorAction
    # SilentlyContinue). Cheaper than piping every running process through
    # Where-Object.
    $busyHits = Get-Process -Name $busyMarkers -ErrorAction SilentlyContinue
    if ($busyHits) {
        $auBusy = @{}
        foreach ($p in $busyHits) { $auBusy[$p.ProcessName] = $true }
    }
} catch {
    Write-DebugLog "AU-busy probe failed: $_"
    $auBusy = $null
}
$auBusyReuse = $false

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
 try {
  # Invalidation triggers, cheapest first so we short-circuit on the common
  # post-TTL cold cache before paying for the args comparison.
  # The whole block is wrapped in try/catch so a cache whose JSON parses
  # but whose date / boot-time fields are non-parseable strings (manual
  # edit, partial truncation, future schema drift) is treated as invalid
  # rather than crashing the script - the cast errors would otherwise
  # propagate past the if-chain.
  if ($null -eq $scanCache.date -or ([datetime]$scanCache.date).AddHours(11) -lt $StartTime) {
    Write-DebugLog "Cache date too old $($scanCache.date) (max 11 h) "
    $cacheIsInvalid = $true
  } elseif ($null -ne $LastSearchSuccessDate -and [datetime]$scanCache.date -lt [datetime]$LastSearchSuccessDate) {
    Write-DebugLog "Cache invalidated by AU scan since cache write"
    $cacheIsInvalid = $true
  } elseif ($null -ne $LastInstallationSuccessDate -and [datetime]$scanCache.date -lt [datetime]$LastInstallationSuccessDate) {
    Write-DebugLog "Cache invalidated by AU installation since cache write"
    $cacheIsInvalid = $true
  } elseif ($null -ne $currentBootTime -and $null -ne $scanCache.LastBootUpTime -and
            [datetime]$scanCache.LastBootUpTime -lt [datetime]$currentBootTime) {
    Write-DebugLog "Cache invalidated by host reboot since cache write - resetting FailureRetryCount"
    $cacheIsInvalid = $true
    $rebootClearedFailures = $true
  } elseif (-not $scanCache.SearchOnlineSuccess) {
    # Previous run failed. Retry on the next tick (and the few after) until we
    # either succeed or hit the consecutive-failure cap, then stop retrying
    # and wait for TTL/AU triggers to drive the next attempt - that bounds the
    # WUA hammering when the underlying cause is persistent (broken proxy, AU
    # service stopped, etc.).
    $prevRetries = 0
    if ($scanCache.PSObject.Properties['FailureRetryCount']) { $prevRetries = [int]$scanCache.FailureRetryCount }
    if ($prevRetries -lt $SearchFailureMaxRetries) {
      Write-DebugLog "Cache invalidated: previous run failed ($prevRetries / $SearchFailureMaxRetries retries so far) - retrying"
      $cacheIsInvalid = $true
    } else {
      Write-DebugLog "Cache reused: previous run failed and max retries reached ($prevRetries / $SearchFailureMaxRetries) - waiting for TTL or AU trigger"
    }
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
 } catch {
  Write-DebugLog "Cache invalidated: semantic corruption while evaluating triggers ($_)"
  $cacheIsInvalid = $true
 }
}

# If the cache would normally be refreshed this tick BUT WUA is busy with
# another download or install, prefer to reuse the existing cache rather than
# serialize our Search() behind the in-flight operation. This avoids both
# stalling the foreground install at 0% and prolonging our own run by the
# duration of that install. We only do this when we have a cache to fall back
# on; with no cache we accept the contention because reporting nothing is
# worse than reporting late.
if ($cacheIsInvalid -and $null -ne $scanCache -and $null -ne $auBusy -and $auBusy.Count -gt 0) {
  $busyList = ($auBusy.Keys | Sort-Object) -join ','
  Write-DebugLog "WUA is busy (processes: $busyList) - reusing existing cache to avoid contention"
  $cacheIsInvalid = $false
  $auBusyReuse = $true
}

if ($cacheIsInvalid) {
  # Decide the service mode outside the runspace so an unknown AU service ID
  # can take the clean-exit path (red Xymon line + lock release) without
  # touching the script-scope state from inside a child runspace.
  if ($isWindows7) {
    $serviceMode = 'Default'
  } elseif ($DefaultAUService.ServiceID -eq '7971f918-a847-4430-9279-4a52d1efe18d') {
    $serviceMode = 'MicrosoftUpdate'
  } elseif ($DefaultAUService.ServiceID -eq '9482f4b4-e343-43b6-b170-9a65bc822c77') {
    $serviceMode = 'WindowsUpdate'
  } else {
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

  $Criteria = "IsInstalled=0 and DeploymentAction=* or IsPresent=1 and DeploymentAction='Uninstallation' or IsInstalled=1 and DeploymentAction='Installation' and RebootRequired=1 or IsInstalled=0 and DeploymentAction='Uninstallation' and RebootRequired=1"

  $SearchOnlineSuccess = $false
  $Updates = $null
  $lastSearchError = $null
  $attempt = 0

  # Each attempt creates its own COM session/searcher inside a timeout-guarded
  # runspace, so a hung Search() (real failure mode seen on collisions with
  # concurrent AU scans) cannot pin the script past the configured cap. The
  # Updates collection is enumerated inside the same runspace because COM
  # objects do not marshal across runspace boundaries; only plain pscustomobjects
  # cross back.
  do {
    $attempt++
    Write-DebugLog "WUA Search attempt $attempt/$SearchAttempts (timeout ${SearchTimeoutSeconds}s, service=$serviceMode)"

    $outcome = Invoke-WithTimeout -TimeoutSeconds $SearchTimeoutSeconds `
      -Arguments @($Computername, $serviceMode, $Criteria) -ScriptBlock {
        param($computerName, $serviceMode, $criteria)
        try {
          $session = [activator]::CreateInstance([type]::GetTypeFromProgID("Microsoft.Update.Session", $computerName))
          $searcher = $session.CreateUpdateSearcher()
          switch ($serviceMode) {
            'MicrosoftUpdate' {
              $searcher.ServiceID       = '7971f918-a847-4430-9279-4a52d1efe18d'
              $searcher.SearchScope     = 1
              $searcher.ServerSelection = 3
            }
            'WindowsUpdate' {
              $searcher.ServiceID = '9482f4b4-e343-43b6-b170-9a65bc822c77'
            }
            # 'Default' (Windows 7) leaves the searcher at its default service.
          }
          $r = $searcher.Search($criteria)
          $list = @()
          for ($i = 0; $i -lt $r.Updates.Count; $i++) {
            $u = $r.Updates.Item($i)
            $list += [pscustomobject]@{
              Title = $u.Title
              KB = $u.KBArticleIDs
              MsrcSeverity = $u.MsrcSeverity
              IsBeta = $u.IsBeta
              IsDownloaded = $u.IsDownloaded
              IsHidden = $u.IsHidden
              IsInstalled = $u.IsInstalled
              IsMandatory = $u.IsMandatory
              IsPresent = $u.IsPresent
              RebootRequired = $u.RebootRequired
              IsUninstallable = $u.IsUninstallable
              Url = $u.MoreInfoUrls
              LastDeploymentChangeTime = $u.LastDeploymentChangeTime
              Categories = ($u.Categories | Select-Object -ExpandProperty Name)
              BundledUpdates = @($u.BundledUpdates) | ForEach-Object {
                [pscustomobject]@{
                  Title = $_.Title
                  DownloadUrl = @($_.DownloadContents).DownloadUrl
                }
              }
            }
          }
          @{ Success = $true; Updates = $list }
        } catch {
          @{ Success = $false; Error = "$_" }
        }
      }

    if ($null -eq $outcome) {
      $lastSearchError = "timed out after ${SearchTimeoutSeconds}s"
      Write-DebugLog "WUA Search() $lastSearchError (attempt $attempt)"
    } elseif ($outcome.Success) {
      $SearchOnlineSuccess = $true
      $Updates = $outcome.Updates
      Write-DebugLog "WUA Search() returned $($Updates.Count) updates (attempt $attempt)"
    } else {
      $lastSearchError = $outcome.Error
      Write-DebugLog "WUA Search() failed (attempt $attempt): $lastSearchError"
    }

    if (-not $SearchOnlineSuccess -and $attempt -lt $SearchAttempts) {
      Write-DebugLog "Sleeping ${SearchRetryDelaySeconds}s before next WUA Search attempt"
      Start-Sleep -Seconds $SearchRetryDelaySeconds
    }
  } until ($SearchOnlineSuccess -or ($attempt -ge $SearchAttempts))

  if ($SearchOnlineSuccess) {
    $SearchOnlineSuccessDate = $StartTime
  }

  # Set $count for the downstream classification loop. Handles $null (no
  # successful search), @() (search succeeded but zero pending updates), and
  # populated arrays in the same expression.
  if ($Updates) { $count = $Updates.Count } else { $count = 0 }

  # FailureRetryCount tracks consecutive failed runs across cache writes:
  # incremented on every actual scan failure, reset to 0 on success. This
  # is the value that the cross-run retry logic above consults to decide
  # whether to retry on the next tick. Lock-blocked exits and AU-busy reuse
  # do not reach this point, so they leave the counter untouched. After a
  # detected reboot we start fresh (count = 1 on the new failure) because
  # the previous chain of failures may have been caused by transient state
  # that the boot just cleared.
  if ($SearchOnlineSuccess) {
    $failureRetryCount = 0
  } elseif ($rebootClearedFailures) {
    $failureRetryCount = 1
  } else {
    $prevRetries = 0
    if ($scanCache -and $scanCache.PSObject.Properties['FailureRetryCount']) {
      $prevRetries = [int]$scanCache.FailureRetryCount
    }
    $failureRetryCount = $prevRetries + 1
  }

  $scan = [pscustomobject]@{
    Args = $PsBoundParameters
    date = $StartTime
    LastBootUpTime = $currentBootTime
    Update = $Updates
    SearchOnlineSuccess = $SearchOnlineSuccess
    SearchOnlineSuccessDate = $SearchOnlineSuccessDate
    FailureRetryCount = $failureRetryCount
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

# Initialise the counters unconditionally so they exist even on the "no
# updates / search failed / no cache" path. Otherwise the downstream
# arithmetic ($criticalCount + ... = $null + $null = $null) produces
# an empty Total line in the report.
$criticalCount  = 0; $criticalOverdue  = 0; $criticalRecent  = 0; $criticalOutput  = ""
$importantCount = 0; $importantOverdue = 0; $importantRecent = 0; $importantOutput = ""
$moderateCount  = 0; $moderateOverdue  = 0; $moderateRecent  = 0; $moderateOutput  = ""
$otherCount     = 0; $otherOverdue     = 0; $otherRecent     = 0; $otherOutput     = ""

if ($count -gt 0) {
  Write-DebugLog "Start assembling output"

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
    if ($wUpdate.IsBeta)          { $Status += "B" } else { $Status += "-" }
    if ($wUpdate.IsDownloaded)    { $Status += "D" } else { $Status += "-" }
    if ($wUpdate.IsHidden)        { $Status += "H" } else { $Status += "-" }
    if ($wUpdate.IsInstalled)     { $Status += "I" } else { $Status += "-" }
    if ($wUpdate.IsMandatory)     { $Status += "M" } else { $Status += "-" }
    if ($wUpdate.IsPresent)       { $Status += "P" } else { $Status += "-" }
    if ($wUpdate.RebootRequired)  { $Status += "R" } else { $Status += "-" }
    if ($wUpdate.IsUninstallable) { $Status += "U" } else { $Status += "-" }

    # Classify (counters only; the overall colour is derived from these once
    # the loop is done, so Set-Colour never needs to run per-update).
    if ($severity -eq "Critical") {
      $criticalCount++
      if ($patchDate -lt $dateCriticalLimit) {
        $criticalOverdue++
      } else {
        $criticalRecent++
      }
      $criticalOutput += "<tr><td>$Severity</td><td>$patchAge</td><td><a href=`"https://support.microsoft.com/help/$KB`" onclick=`"window.open(this.href); return false;`">$KB</a></td><td>$Status</td><td>$Title</td></tr>`r`n"

    } elseif ($severity -eq "Important") {
      $importantCount++
      if ($patchDate -lt $dateImportantLimit) {
        $importantOverdue++
      } else {
        $importantRecent++
      }
      $importantOutput += "<tr><td>$Severity</td><td>$patchAge</td><td><a href=`"https://support.microsoft.com/help/$KB`" onclick=`"window.open(this.href); return false;`">$KB</a></td><td>$Status</td><td>$Title</td></tr>`r`n"

    } elseif ($severity -eq "Moderate") {
      $moderateCount++
      if ($patchDate -lt $dateModerateLimit) {
        $moderateOverdue++
      } else {
        $moderateRecent++
      }
      $moderateOutput += "<tr><td>$Severity</td><td>$patchAge</td><td><a href=`"https://support.microsoft.com/help/$KB`" onclick=`"window.open(this.href); return false;`">$KB</a></td><td>$Status</td><td>$Title</td></tr>`r`n"

    } else {
      $otherCount++
      if ($patchDate -lt $dateOtherLimit) {
        $otherOverdue++
      } else {
        $otherRecent++
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
}

# Single source of truth: derive the updates-only colour from the counters.
# Any Critical present escalates to yellow (Critical: 0 days policy);
# Critical overdue (> $CriticalLimit days) escalates to red; non-critical
# buckets contribute yellow only when overdue.
$totalUpdates = $criticalCount + $importantCount + $moderateCount + $otherCount
if ($criticalOverdue -gt 0) {
    $overallColour = "red"
} elseif ($criticalCount -gt 0 -or $importantOverdue -gt 0 -or $moderateOverdue -gt 0 -or $otherOverdue -gt 0) {
    $overallColour = "yellow"
} else {
    $overallColour = "green"
}

# Xymon header colour starts from the updates-only signal, then absorbs
# external health modifiers (AU scan freshness, pending reboot, compliance,
# online search reachability). Keeping these separate from $overallColour
# lets the "Total update(s) available" line stay an honest reflection of
# update severity, while the header reflects the overall host health.
$colour = $overallColour

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

# Soft modifiers - operational signals that warrant attention but not an alarm.
if ($PendingReboot -or -not $SearchOnlineSuccess) {
  $colour = Set-Colour $colour "yellow"
}

# SCONFIG compliance is escalated to red rather than yellow: the operator
# explicitly opted into the check (either via -CheckSConfig or the implicit
# "Download" default), so a deviation is an intentional policy violation, not
# background noise. Aligns the global Xymon status with the inline "&red
# Compliance SCONFIG: ... compliant=False" the report already emits.
if (-not $compliantWinUpdateReg) {
  $colour = Set-Colour $colour "red"
}

$outputText = $outputText + "$colour+12h {0:$DateFormatYMDHMS}`r`n" -f $StartTime
$outputText = $outputText + "<h2>Windows Updates Check</h2>`r`n"

# Report body uses a flat key : value layout grouped into "--- Section ---"
# blocks. Every line in Configuration and Scan is parseable with a single
# regex: ^([^:]+?)\s*:\s*(.+)$ - section headers match ^---\s+(.+)\s+---$.

$outputText += "--- Configuration ----------------------------------------`r`n"
$outputText += "{0,-22} : {1}`r`n"  -f "Criticality level",   $CriticalityLevel
$outputText += "{0,-22} : {1} d`r`n" -f "AU scan max age",    $AutoUpdateMaxAgeDays
$outputText += "{0,-22} : {1}`r`n"  -f "Pending renames max", $PendingFileRenameThreshold
$outputText += "`r`nSeverity thresholds (days):`r`n"
$outputText += "| Bucket    | Yellow | Red |`r`n"
$outputText += "| --------- | ------ | --- |`r`n"
$outputText += "| {0,-9} | {1,-6} | {2,-3} |`r`n" -f "Critical",  0,                $CriticalLimit
$outputText += "| {0,-9} | {1,-6} | {2,-3} |`r`n" -f "Important", $ImportantLimit, "n/a"
$outputText += "| {0,-9} | {1,-6} | {2,-3} |`r`n" -f "Moderate",  $ModerateLimit,  "n/a"
$outputText += "| {0,-9} | {1,-6} | {2,-3} |`r`n" -f "Other",     $OtherLimit,     "n/a"

$outputText += "`r`n--- Scan -------------------------------------------------`r`n"

if ($null -ne $DefaultAUService) {
    $serviceValue = switch ($DefaultAUService.ServiceID.ToLower()) {
        '7971f918-a847-4430-9279-4a52d1efe18d' { "Microsoft Update" }
        '9482f4b4-e343-43b6-b170-9a65bc822c77' { "&yellow Windows Update (Expected Microsoft Update)" }
        default { "$($DefaultAUService.Name) (ServiceID: $($DefaultAUService.ServiceID))" }
    }
} else {
    $serviceValue = "&red Unable to detect default update service"
}
$outputText += "{0,-22} : {1}`r`n" -f "Update service",     $serviceValue
$outputText += "{0,-22} : {1}`r`n" -f "Searching duration", $RunTime.ToString('hh\:mm\:ss\.fff')

if (-not $AutoScanExpected) {
    if ($null -eq $LastSearchSuccessDate) {
        $auScanValue = "n/a (not evaluated in $currentName mode)"
    } else {
        $auScanValue = "{0:$DateFormatYMDHMS} (not evaluated in $currentName mode)" -f $LastSearchSuccessDate
    }
} elseif ($null -eq $LastSearchSuccessDate) {
    $auScanValue = "&red n/a (Automatic Updates API unresponsive or never scanned)"
} else {
    $selfSearchAgeDays = [math]::Round((New-TimeSpan -Start $LastSearchSuccessDate -End (Get-Date)).TotalDays, 1)
    if ($selfSearchAgeDays -gt $AutoUpdateMaxAgeDays) {
        $auScanValue = "&yellow {0:$DateFormatYMDHMS} (stale: $selfSearchAgeDays days old, threshold $AutoUpdateMaxAgeDays)" -f $LastSearchSuccessDate
    } else {
        $auScanValue = "{0:$DateFormatYMDHMS}" -f $LastSearchSuccessDate
    }
}
$outputText += "{0,-22} : {1}`r`n" -f "Last AU service scan", $auScanValue

if ($null -eq $SearchOnlineSuccessDate) {
    $probeValue = "&red n/a (no successful online scan)"
} else {
    $probeValue = "{0:$DateFormatYMDHMS}" -f $SearchOnlineSuccessDate
}
$outputText += "{0,-22} : {1}`r`n" -f "Last probe online",    $probeValue

if ($auBusyReuse) {
    $busyList = ($auBusy.Keys | Sort-Object) -join ', '
    $outputText += "{0,-22} : AU busy ({1}) - reusing last cache`r`n" -f "Skipped WUA Search", $busyList
}

if (-not $SearchOnlineSuccess) {
    # The retry count comes from the cache we either just wrote (this run
    # failed) or are reusing (this tick chose not to scan). $failureRetryCount
    # is set only when we wrote a failure; otherwise we pull from $scanCache.
    $retryShown = 0
    if ($null -ne $failureRetryCount) {
        $retryShown = $failureRetryCount
    } elseif ($scanCache -and $scanCache.PSObject.Properties['FailureRetryCount']) {
        $retryShown = [int]$scanCache.FailureRetryCount
    }
    if ($retryShown -ge $SearchFailureMaxRetries) {
        $retryNote = "retry cap reached ($retryShown/$SearchFailureMaxRetries) - waiting for TTL or AU trigger"
    } else {
        $retryNote = "retry $retryShown/$SearchFailureMaxRetries"
    }
    # $lastSearchError is only populated when we actually attempted a search this
    # run; if the failure was carried over from a cached previous run, we don't
    # have a specific message to surface.
    if ($lastSearchError) {
        $unreachableValue = "&yellow $retryNote - last: $lastSearchError"
    } else {
        $unreachableValue = "&yellow $retryNote - cached failure from previous run"
    }
    $outputText += "{0,-22} : {1}`r`n" -f "Update unreachable", $unreachableValue
}

$outputText += "`r`n--- Compliance -------------------------------------------`r`n"
$outputText += $compliantOutputText

$outputText += "`r`n"

# --- Summary output ---
# $totalUpdates and $overallColour were computed earlier (single source of truth);
# the Total line is now always emitted with the colour we already derived.
$outputText += "&$overallColour Total update(s) available: $totalUpdates`r`n"

if ($totalUpdates -gt 0) {
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

if ($PendingReboot) {
  $reasonsText = ($result.Reasons -join ", ")
  $outputText += "&yellow Reboot pending: $reasonsText`r`n"
}

# Always surface the queued file rename operations when there are any, even if
# their count stays under the alert threshold - the operator may want to see
# what is sitting in the queue regardless of whether it is currently raising
# an alarm. Match the rest of the report's convention: emit a colour marker
# only when the line is in alert state, otherwise let it render neutral.
$pfrCount = $result.PendingFileRenames.Count
if ($pfrCount -gt 0) {
  if ($pfrCount -gt $result.PendingFileRenameThreshold) {
    $outputText += "&yellow Pending file renames: $pfrCount entries (over threshold $($result.PendingFileRenameThreshold))`r`n"
  } else {
    $outputText += "Pending file renames: $pfrCount entries (within threshold $($result.PendingFileRenameThreshold))`r`n"
  }
  # Indent the list so it reads as a sub-block of the line above.
  foreach ($f in $result.PendingFileRenames) {
    $outputText += "  $f`r`n"
  }
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
