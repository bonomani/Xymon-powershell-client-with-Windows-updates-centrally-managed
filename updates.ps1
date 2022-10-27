###############################################################################
# Script written by someone else and modified by Kris Springer, Bonomani
# https://www.krisspringer.com
# https://www.ionetworkadmin.com
# Version 0.2 / 27.10.2022 - Updated Script - Bonomani
###############################################################################
<#
.SYNOPSIS
   This script reports Windows Updates

. DESCRIPTION

.EXAMPLE
In /etc/client-local.cfg you can use the "default config" (not implement experimental feature)

[powershell]
external:slowscan:async:bb://updates.ps1|MD5|69df8284b1448bb56d0d71fb957af4e4|powershell.exe|-executionpolicy remotesigned -file "{script}"

Experimental: detect Workstation or Server and check for compliance: 
- Workstation for "default" udpate registry settings 
- Server for "manual" update registry settings

[powershell]
external:slowscan:async:bb://updates.ps1|MD5|69df8284b1448bb56d0d71fb957af4e4|powershell.exe|-executionpolicy remotesigned -file "{script}" -checkdefaultcompliance

And you can override those seeting with yours un the client
[powershell]
external:slowscan:async:bb://updates.ps1|MD5|69df8284b1448bb56d0d71fb957af4e4|powershell.exe|-executionpolicy remotesigned -file "{script}" -checkdefaultcompliance -NoAutoUpdate 1 -AutoInstallMinorUpdates $null -ElevateNonAdmins $null

Experimental options (can be change withour notice)
-checkdefaultcompliance
-AUOptions [int]
-NoAutoUpdate [int]
-AutoInstallMinorUpdates [int]
-ElevateNonAdmins [int]
-From [string](wu:Windows Update, mu:Microsoft Update)
-Version

#>
[CmdletBinding()]
param(
  [Parameter()]
  [AllowEmptyString()]
  [string]$From,#mu=Microsoft Update, wu Windows Update
  #                                                                 Default                       Recommended to Disable Auto Update         Do not download at all
  [string]$AUOptions,#               Usually not exist by default = 3:Download and notify update, 3                                          2: Do not download
  [string]$NoAutoUpdate,#            Usually not exist by default = 0:Autopdate,                  1:Disable autopdate
  [string]$AutoInstallMinorUpdates,# Usually not exist by default = 1:AutoInstallMinorUpdates,    0:Disable AutoInstallMinorUpdates
  [string]$ElevateNonAdmins,#        Usually not exist by default = 1:ElevateNonAdmins            0;Disable ElevateNonAdmins
  [switch]$Version,
  [switch]$CheckDefaultCompliance # Option above overwritte some default
)
$ScriptVersion = 0.2

$CriticalLimit = 14 # Delay critical updates alarm for days
$ModerateLimit = $CriticalLimit # Delay moderate updates alarm for days
$OtherLimit = 2 * $ModerateLimit # Delay other updates alarm for days
$logFile = 'c:\Program Files\xymon\ext\updates.log'
$outputFile = 'c:\Program Files\xymon\tmp\updates'
$MSRetries = 1 # Windows update retries Timeout = 10min, Max time retries = $MSRetries X timeout
$debug = 0 # Write to logfile 

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

function Test-PendingReboot
<#
.SYNOPSIS
    This function checks diffrent Registry Keys and Values do determine if a Reboot is pending.

.DESCRIPTION
    Based on previous work by Kris Springer
    Based on the work of Andres Bohren https://blog.icewolf.ch/archive/2020/07/03/check-for-pending-reboot-with-powershell.aspx
    He found a Table on the Internet and decided to Write a Powershell Script to check if a Reboot is pending.
    Not all Keys are checked. But feel free to extend the Script.

 https://adamtheautomator.com/pending-reboot-registry-windows/
 KEY VALUE CONDITION
 HKLM:\SOFTWARE\Microsoft\Updates UpdateExeVolatile Value is anything other than 0
 HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager PendingFileRenameOperations value exists
 HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager PendingFileRenameOperations2 value exists
 HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired NA key exists
 HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Services\Pending NA Any GUID subkeys exist
 HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\PostRebootReporting NA key exists
 HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce DVDRebootSignal value exists
 HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending NA key exists
 HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootInProgress NA key exists
 HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\PackagesPending NA key exists
 HKLM:\SOFTWARE\Microsoft\ServerManager\CurrentRebootAttempts NA key exists
 HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon JoinDomain value exists
 HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon AvoidSpnSet value exists
 HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName ComputerName Value ComputerName in HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName is different
#>
{
  [bool]$PendingReboot = $false
  #Check for Keys
  if ((Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") -eq $true) {
    Write-DebugLog "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
    $PendingReboot = $true
  }
  if ((Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\PostRebootReporting") -eq $true) {
    Write-DebugLog "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\PostRebootReporting"
    $PendingReboot = $true
  }
  if ((Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") -eq $true) {
    Write-DebugLog "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
    $PendingReboot = $true
  }
  if ((Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") -eq $true) {
    Write-DebugLog "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
    $PendingReboot = $true
  }
  if ((Test-Path -Path "HKLM:\SOFTWARE\Microsoft\ServerManager\CurrentRebootAttempts") -eq $true) {
    Write-DebugLog "HKLM:\SOFTWARE\Microsoft\ServerManager\CurrentRebootAttempts"
    $PendingReboot = $true
  }
  #Check for Values
  if ((Test-RegistryValue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing" -Value "RebootInProgress") -eq $true) {
    Write-DebugLog "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing > RebootInProgress"
    $PendingReboot = $true
  }
  if ((Test-RegistryValue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing" -Value "PackagesPending") -eq $true) {
    Write-DebugLog "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing > PackagesPending"
    $PendingReboot = $true
  }
  if ((Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Value "PendingFileRenameOperations") -eq $true) {
    Write-DebugLog "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager > PendingFileRenameOperations"
    $PendingReboot = $true
  }
  if ((Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Value "PendingFileRenameOperations2") -eq $true) {
    Write-DebugLog "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager > PendingFileRenameOperations2"
    $PendingReboot = $true
  }
  if ((Test-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -Value "DVDRebootSignal") -eq $true) {
    Write-DebugLog "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce > DVDRebootSignal"
    $PendingReboot = $true
  }
  if ((Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon" -Value "JoinDomain") -eq $true) {
    Write-DebugLog "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon > JoinDomain"
    $PendingReboot = $true
  }
  if ((Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon" -Value "AvoidSpnSet") -eq $true) {
    Write-DebugLog "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon > AvoidSpnSet"
    $PendingReboot = $true
  }
  try {
    $util = [wmiclass]"\\.\root\ccm\clientsdk:CCM_ClientUtilities"
    $status = $util.DetermineIfRebootPending()
    if (($status -ne $null) -and $status.RebootPending) {
      Write-DebugLog "\\.\root\ccm\clientsdk:CCM_ClientUtilities"
      $PendingReboot = $true
    }
  } catch {}
  return $PendingReboot
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

function Write-DebugLog {
  param(
    [string]$message,
    [string]$filepath = $logFile
  )
  $datestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
  if ($debug) { Add-Content -Path $filepath -Value "$datestamp  $message" }
}

if ($Version) {
  Write-Host $ScriptVersion
  exit
}

$dateCriticalLimit = (Get-Date).adddays(- $CriticalLimit)
$dateModerateLimit = (Get-Date).adddays(- $ModerateLimit)
$dateOtherLimit = (Get-Date).adddays(- $OtherLimit)
$Computername = $env:COMPUTERNAME
# Get OS: $osversionLookup[$osVersion]
$os = Get-WmiObject Win32_OperatingSystem
$osVersion = $os.version
if (([version]$osVersion).Major -eq "10") { $osVersion = "$(([version]$osVersion).Major).$(([version]$osVersion).Minor).*" }
$osversionLookup = @{ "5.1.2600" = "XP"; "5.1.3790" = "2003"; "6.0.6001" = "Vista/2008"; "6.1.7600" = "Win7/2008R2"; "6.1.7601" = "Win7 SP1/2008R2 SP1"; "6.2.9200" = "Win8/2012"; "6.3.9600" = "Win8.1/2012R2"; "10.0.*" = "Windows 10/Server 2016" };

Write-DebugLog "Searching for PendingReboot"
$PendingReboot = Test-PendingReboot
$CheckCompliance = $CheckDefaultCompliance -or -not [string]::IsNullOrEmpty($AUOptions) -or -not [string]::IsNullOrEmpty($NoAutoUpdate) -or -not [string]::IsNullOrEmpty($AutoInstallMinorUpdates) -or -not [string]::IsNullOrEmpty($ElevateNonAdmins)

# Check Compliance Set default
if ($CheckCompliance) {
  # SET DEFAULT AND GATHERS ALL DATA
  $regPathAU = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
  $regPathWindowsUpdate = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'
  $regPropertyAUOptions = 'AUOptions'
  $regPropertyNAU = 'NoAutoUpdate'
  $regPropertyAIMU = 'AutoInstallMinorUpdates'
  $regPropertyENA = 'ElevateNonAdmins'
  $regAU = Get-ItemProperty -Path $regPathAU -ErrorAction SilentlyContinue
  $regWindowsUpdate = Get-ItemProperty -Path $regPathWindowsUpdate -ErrorAction SilentlyContinue
  $regValueAUOptions = $regAU.$regPropertyAUOptions
  $regValueNAU = $regAU.$regPropertyNAU
  $regValueAIMU = $regAU.$regPropertyAIMU
  $regValueAIMU = $regAU.$regPropertyAIMU
  $regValueENA = $regWindowsUpdate.$regPropertyENA
  if ($CheckDefaultCompliance) {
    if ((Get-WmiObject -Class Win32_OperatingSystem).ProductType -eq 1) { #Workstation: Use default 
      $defaultUProfile = "Workstation"
      $defaultAUOptions = $null # 3 if defaultNoAutoUpdate<>1 
      $defaultNoAutoUpdate = $null #0
      $defaultAutoInstallMinorUpdates = $null #1
      $defaultElevateNonAdmins = $null # 1
    } else { #Server:  default to "Manual"
      $defaultUProfile = "Server"
      $defaultAUOptions = 1
      $defaultNoAutoUpdate = 1
      $defaultAutoInstallMinorUpdates = 0
      $defaultElevateNonAdmins = 0
    }
    if (-not $PSBoundParameters.ContainsKey($regPropertyAUOptions)) {
      $AUOptions = $defaultAUOptions
    } else {
      if ($AUOptions -eq '$null') {
        $AUOptions = $null
      }
    }
    if (-not $PSBoundParameters.ContainsKey($regPropertyNAU)) {
      $NoAutoUpdate = $defaultNoAutoUpdate
    } else {
      if ($NoAutoUpdate -eq '$null') {
        $NoAutoUpdate = $null
      }
    }
    if (-not $PSBoundParameters.ContainsKey($regPropertyAIMU)) {
      $AutoInstallMinorUpdates = $defaultAutoInstallMinorUpdates
    } else {
      if ($AutoInstallMinorUpdates -eq '$null') {
        $AutoInstallMinorUpdates = $null
      }
    }
    if (-not $PSBoundParameters.ContainsKey($regPropertyENA)) {
      $ElevateNonAdmins = $defaultElevateNonAdmins
    } else {
      if ($ElevateNonAdmins -eq '$null') {
        $ElevateNonAdmins = $null
      }
    }
  }
  Write-DebugLog "Searching for windows update registry compliance"
  # Check registry key/value for windows update

  $compliantOutputText = ""
  $sconfigUpdate = $null
  # TRANSLATES REGISTRY FOR WINDOWS UPDATE TO USER FRIENDLY OUTPUT: SCONFIG like
  if ($regValueNAU -eq 1) {
    if (($regValueAUOptions -eq $null) -or ($regValueAUOptions -eq 1)) {
      $sconfigUpdate = "Manual"

    }
  } elseif (($regValueNAU -eq $null) -or ($regValueNAU -eq 0)) {
    switch ($regValueAUOptions) {
      $null { $sconfigUpdate = "Download"; break }
      1 { $sconfigUpdate = "Manual"; break }
      2 { $sconfigUpdate = "Notify before downloading (AUOptions=2)"; break }
      3 { $sconfigUpdate = "Download"; break }
      4 { $sconfigUpdate = "Automatic"; break }
    }
  }
  if ($sconfigUpdate -eq $null) {
    $compliantOutputText = $compliantOutputText + "&yellow Compliance SCONFIG profil: Invalid (Incompatibility between AUOptions=$regValueAUOptions and NoAutoUpdate=$regValueNAU)`r`n"
  } else {
    $compliantOutputText = $compliantOutputText + "&green Compliance SCONFIG profile: $sconfigUpdate`r`n"
  }
  $compliantOutputText = $compliantOutputText + "Checking compatibility with profile for: $defaultUProfile`r`n"

  # Retrieve current values for comparison
  $compliantWinUpdateReg = $True
  if (([string]$regValueAUOptions -ne $AUOptions) -and -not (($regValueAUOptions -eq $null) -and ($AUOptions -eq ''))) {
    Write-DebugLog "Not compliant AUOptions: $regValueAUOptions`r`n"
    $compliantWinUpdateReg = $False
    if ($AUOptions -eq $null) {
      $compliantOutputText = $compliantOutputText + "&yellow Compliance $regPathAU\$regPropertyAUOptions : $regValueAUOptions (No key expected)`r`n"
    } else {
      $compliantOutputText = $compliantOutputText + "&yellow Compliance $regPathAU\$regPropertyAUOptions : $regValueAUOptions (expected: $AUOptions)`r`n"
    }
  } else {
    $compliantOutputText = $compliantOutputText + "&green Compliance $regPathAU\$regPropertyAUOptions : $regValueAUOptions`r`n"
  }

  if (([string]$regValueNAU -ne $NoAutoUpdate) -and -not (($regValueNAU -eq $null) -and ($NoAutoUpdate -eq ''))) {
    $test = $NoAutoUpdate -eq $null
    Write-DebugLog "Not compliant NoAutoUpdate: $regValueNAU `r`n"
    $compliantWinUpdateReg = $False
    if ($NoAutoUpdate -eq $null) {
      $compliantOutputText = $compliantOutputText + "&yellow Compliance $regPathAU\$regPropertyNAU : $regValueNAU (No key expected)`r`n"
    } else {
      $compliantOutputText = $compliantOutputText + "&yellow Compliance $regPathAU\$regPropertyNAU : $regValueNAU (expected: $NoAutoUpdate)`r`n"
    }
  } else {
    Write-DebugLog "1: $regValueNAU 2:$NoAutoUpdate"
    $compliantOutputText = $compliantOutputText + "&green Compliance $regPathAU\$regPropertyNAU : $regValueNAU`r`n"
  }
  if ($osversionLookup[$osVersion] -ne "Windows 10/Server 2016") { # Dirty Remove defer feature
    if (([string]$regValueAIMU -ne $AutoInstallMinorUpdates) -and -not (($regValueAIMU -eq $null) -and ($AutoInstallMinorUpdates -eq ''))) {
      Write-DebugLog "Not compliant AutoInstallMinorUpdates: $regValueAIMU"
      $compliantWinUpdateReg = $False
      if ($AutoInstallMinorUpdates -eq $null) {
        $compliantOutputText = $compliantOutputText + "&yellow Compliance $regPathAU\$regPropertyAIMU : $regValueAIMU (No key expected)`r`n"
      } else {
        $compliantOutputText = $compliantOutputText + "&yellow Compliance $regPathAU\$regPropertyAIMU : $regValueAIMU (expected: $AutoInstallMinorUpdates)`r`n"
      }
    } else {
      $compliantOutputText = $compliantOutputText + "&green Compliance $regPathAU\$regPropertyAIMU : $regValueAIMU`r`n"
    }

    if (([string]$regValueENA -ne $ElevateNonAdmins) -and -not (($regValueENA -eq $null) -and ($ElevateNonAdmins -eq ''))) {
      Write-DebugLog "Not compliant ElevateNonAdmins: $regValueENA"
      $compliantWinUpdateReg = $False
      if ($ElevateNonAdmins -eq $null) {
        $compliantOutputText = $compliantOutputText + "&yellow Compliance $regPathWindowsUpdate\$regPropertyENA : $regValueENA (No key expected)`)`r`n"
      } else {
        $compliantOutputText = $compliantOutputText + "&yellow Compliance $regPathWindowsUpdate\$regPropertyENA : $regValueENA (expected: $ElevateNonAdmins)`r`n"
      }
    } else {
      $compliantOutputText = $compliantOutputText + "&green Compliance $regPathWindowsUpdate\$regPropertyENA : $regValueENA`r`n"
    }

  }
}

Write-DebugLog "Creating update session"
$updatesession = [activator]::CreateInstance([type]::GetTypeFromProgID("Microsoft.Update.Session",$Computername))
Write-DebugLog "Creating update searcher"
$UpdateSearcher = $updatesession.CreateUpdateSearcher()
Write-DebugLog "Searching for updates"
if (((Get-WmiObject Win32_OperatingSystem).Name) -notlike "*Windows 7*") {
  #$UpdateSearcher.ServiceID = '7971f918-a847-4430-9279-4a52d1efe18d' # Microsoft Update online
  #$currentServiceID = ((New-Object -ComObject "Microsoft.Update.ServiceManager").Services | Where {$_.IsDefaultAUService}).ServiceID # Current Service
  #$UpdateSearcher.ServiceID = '7971f918-a847-4430-9279-4a52d1efe18d'.ToUUID() 
  if (-not [string]::IsNullOrEmpty($From)) {
    if ($From -eq "mu") {
      $ServiceName = "Microsoft Update"
      $UpdateSearcher.ServiceID = '7971f918-a847-4430-9279-4a52d1efe18d'
      $UpdateSearcher.SearchScope = 1 # MachineOnly
      $UpdateSearcher.ServerSelection = 3 # Windows Update (2) Microsoft Update (3)
    } elseif ($From -eq "wu") {
      $ServiceName = "Windows Update"
      $ServiceID = '9482f4b4-e343-43b6-b170-9a65bc822c77'
    } else {
      # Fallback to Mirocoft Update
      $ServiceName = "Microsoft Update"
      $UpdateSearcher.ServiceID = '7971f918-a847-4430-9279-4a52d1efe18d'
    }
  } else {
    $DefaultAUService = (((New-Object -ComObject "Microsoft.Update.ServiceManager").Services | Where-Object { $_.IsDefaultAUService })) | Select-Object ServiceID,Name
    $ServiceName = $DefaultAUService.Name
    if ($DefaultAUService.ServiceID -eq '7971f918-a847-4430-9279-4a52d1efe18d') {
      $UpdateSearcher.ServiceID = '7971f918-a847-4430-9279-4a52d1efe18d'
      $UpdateSearcher.SearchScope = 1 # MachineOnly
      $UpdateSearcher.ServerSelection = 3 # Windows Update (2) Microsoft Update (3)
    } elseif ($DefaultAUService.ServiceID -eq '9482f4b4-e343-43b6-b170-9a65bc822c77') {
      $UpdateSearcher.ServiceID = '7971f918-a847-4430-9279-4a52d1efe18d'
    } else {
      exit
    }
  }
}

$MSSts = $false
$MSCount = 0
$MSStartTime = Get-Date
do {
  try {
    $Criteria = "(IsInstalled=0 and DeploymentAction=*) or (IsPresent=1 and DeploymentAction='Uninstallation') or (IsInstalled=1 and DeploymentAction='Installation') and RebootRequired=1"
    $searchresult = $updatesearcher.Search($Criteria)
    $MSSts = $true
  } catch {
  }
  $MSCount++
} until ($MSSts -or $MSCount -eq $MSRetries)
$MSTimeSpan = New-TimeSpan -Start $MSStartTime -End (Get-Date)
$MSRunTime = $MSTimeSpan.ToString("hh':'mm':'ss")

$Updates = if ($searchresult.Updates.Count -gt 0) {
  #Updates are  waiting to be installed
  #Cache the  count to make the For loop run faster
  $count = $searchresult.Updates.Count
  Write-DebugLog "$count updates have been found"
  Write-DebugLog "Looping through updates to retrieve information"
  for ($i = 0; $i -lt $Count; $i++) {
    #Create object holding updates
    $Update = $searchresult.Updates.Item($i)
    [pscustomobject]@{
      Title = $Update.Title
      KB = $($Update.KBArticleIDs)
      SecurityBulletin = $($Update.SecurityBulletinIDs)
      MsrcSeverity = $Update.MsrcSeverity
      IsInstalled = $Update.IsInstalled
      IsDownloaded = $Update.IsDownloaded
      IsHidden = $Update.IsHidden
      RebootRequired = $Update.RebootRequired
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

if ($count -gt 0) {
  Write-DebugLog "Start assembling output"
  $criticalCount = 0
  $criticalOutput = ""
  $moderateCount = 0
  $moderateOutput = ""
  $otherCount = 0
  $otherOutput = ""
  $colour = "green"
  foreach ($wUpdate in $Updates) {
    $severity = $wUpdate.MsrcSeverity
    $bulletin = $wUpdate.SecurityBulletin
    $patchDate = $wUpdate.LastDeploymentChangeTime
    $patchAge = (New-TimeSpan -Start $patchDate -End (Get-Date)).Days
    $kb = $wUpdate.KB
    $IsInstalled = $wUpdate.IsInstalled
    $IsDownloaded = $wUpdate.IsDownloaded
    $IsHidden = $wUpdate.IsHidden
    $RebootRequired = $wUpdate.RebootRequired
    $title = $wUpdate.Title
    if ($Severity -eq "Critical" -and -not $IsHidden) {
      if ($patchDate -lt $dateCriticalLimit) {
        $colour = Set-Colour $colour "red"
      } else {
        $colour = Set-Colour $colour "yellow"
      }
      $criticalCount = $criticalCount + 1
      $criticalOutput = $criticalOutput + "<tr><td style=`"colour:red;`">$Severity</td><td>$patchAge</td><td><a href=`"https://technet.microsoft.com/en-us/library/security/$bulletin.aspx`" target=`"_blank`">$Bulletin</a></td><td><a href=`"https://support.microsoft.com/en-us/kb/$KB`" target=`"_blank`">$KB</a></td><td>$IsInstalled</td><td>$IsDownloaded</td><td>$Downloaded</td><td>$IsHidden</td><td>$RebootRequired</td><td>$Title</td></tr>`r`n"
    } elseif ($Severity -eq "Moderate" -or $Severity -eq "Important" -and -not $IsHidden) {
      if ($patchDate -lt $dateModerateLimit) {
        $colour = Set-Colour $colour "yellow"
      } else {
        $colour = Set-Colour $colour "green"
      }
      $moderateCount = $moderateCount + 1
      $moderateOutput = $moderateOutput + "<tr><td style=`"colour:yellow;`">$Severity</td><td>$patchAge</td><td><a href=`"https://technet.microsoft.com/en-us/library/security/$bulletin.aspx`" target=`"_blank`">$Bulletin</a></td><td><a href=`"https://support.microsoft.com/en-us/kb/$KB`" target=`"_blank`">$KB</a></td><td>$IsInstalled</td><td>$IsDownloaded</td><td>$IsHidden</td><td>$RebootRequired</td><td>$Title</td></tr>`r`n"
    } else {
      if ($patchDate -lt $dateOtherLimit) {
        $colour = Set-Colour $colour "yellow"
      } else {
        $colour = Set-Colour $colour "green"
      }
      $otherCount = $otherCount + 1
      $otherOutput = $otherOutput + "<tr><td>Other</td><td>$patchAge</td><td><a href=`"https://technet.microsoft.com/en-us/library/security/$bulletin.aspx`" target=`"_blank`">$Bulletin</a></td><td><a href=`"https://support.microsoft.com/en-us/kb/$KB`" target=`"_blank`">$KB</a></td><td>$IsInstalled</td><td>$IsDownloaded</td><td>$IsHidden</td><td>$RebootRequired</td><td>$Title</td></tr>`r`n"
    }
  }
  if ($criticalCount -eq 0) {
    Write-DebugLog "No critical updates"
  }
} else {
  Write-DebugLog "No updates found"
  $colour = "green"
}

if ($PendingReboot -or -not $MSsts -or -not $compliantWinUpdateReg) {
  $colour = Set-Colour $colour "yellow"
}

Write-DebugLog "Get hostname"
$fqdnHostname = [System.Net.DNS]::GetHostByName('').HostName.ToLower()
Write-DebugLog "Get current date"
$dateString = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$outputText = $outputText + "$colour+12h $dateString`r`n"
$outputText = $outputText + "<h2>Windows Updates Check</h2>`r`n"
$outputText = $outputText + "Delay critical update alarms in [days]: $CriticalLimit`r`n"
$outputText = $outputText + "Delay moderate update alarms in [days]: $ModerateLimit`r`n"
$outputText = $outputText + "Delay other update alarms [days]: $OtherLimit`r`n"
$outputText = $outputText + "Update service: $ServiceName`r`n"
$outputText = $outputText + "Updates searching time: $MSRunTime`r`n"
if ($CheckCompliance) {

  $outputText = $outputText + $compliantOutputText
}
if ($MSsts) {
  if ($count) {
    $outputText = $outputText + "&yellow Total update(s) available: $count`r`n"
  } else {
    $outputText = $outputText + "&green Total update(s) available: 0`r`n"
  }
} else {
  $outputText = $outputText + "&yellow Update is unreachable after retries: $MSRetries`r`n"
}
if ($criticalCount -gt 0) {
  Write-DebugLog "Red colour due to critical updates"
  $outputText = $outputText + "&red Critical update(s) available: $criticalCount`r`n"
}
if ($moderateCount -gt 0) {
  Write-DebugLog "Yellow colour due to moderate updates"
  $outputText = $outputText + "&yellow Moderate update(s) available: $moderateCount`r`n"
}
if ($otherCount -gt 0) {
  Write-DebugLog "Green colour due to other updates"
  $outputText = $outputText + "&green Other update(s) available: $otherCount`r`n"
}
if ($PendingReboot) {
  $outputText = $outputText + "&yellow Reboot pending`r`n"
}
if ($count -gt 0) {
  Write-DebugLog "Updates have been detected so output contains updates listing"
  $outputText = $outputText + "<p>&nbsp;</p>`r`n"
  $outputText = $outputText + "<style>table.updates, table.updates th, table.updates td {border: 1px solid silver; border-collapse:collapse; padding:5px; background-color:black;}</style>`r`n"
  $outputText = $outputText + "<table class=`"updates`"><tr><th>Severity</th><th>Age (days)</th><th>Bulletin</th><th>KB</th><th>Installed</th><th>Downloaded</th><th>Hidden</th><th>RebootRequired</th><th>Title</th></tr>`r`n"
  $outputText = $outputText + $criticalOutput
  $outputText = $outputText + $moderateOutput
  $outputText = $outputText + $otherOutput
  $outputText = $outputText + "</table>`r`n"
}

Write-DebugLog "Save contents into tmp file"
$outputText | Set-Content $outputFile
