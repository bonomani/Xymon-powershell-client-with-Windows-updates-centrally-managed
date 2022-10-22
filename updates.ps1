# Script written by someone else and modified by Kris Springer and Bonomani
# https://www.krisspringer.com
# https://www.ionetworkadmin.com
#
# This script reports Windows Updates
$dayLimit   = 14
$logFile = 'c:\Program Files\xymon\ext\updates.log'
$outputFile = 'C:\Program Files\xymon\tmp\updates'

function Test-PendingReboot
{
  if (Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -EA SilentlyContinue) { return $true }
  if (Get-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -EA SilentlyContinue) { return $true }
  try {
    $util = [wmiclass]"\\.\root\ccm\clientsdk:CCM_ClientUtilities"
    $status = $util.DetermineIfRebootPending()
    if (($status -ne $null) -and $status.RebootPending) {
      return $true
    }
  } catch {}

  return $false
}

## This section controls the reporting colors.
## I've forced them all green so I can use the script for information instead of alerts.
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
  $message | Out-File $filepath -Append
}

$LogTime = Get-Date -Format "MM-dd-yyyy_hh-mm-ss"
Write-DebugLog $LogTime
$outputText = ""
$dateLimit = (Get-Date).adddays(-$dayLimit)
$Computername = $env:COMPUTERNAME
Write-DebugLog "Creating update session"
$updatesession = [activator]::CreateInstance([type]::GetTypeFromProgID("Microsoft.Update.Session",$Computername))
Write-DebugLog "Creating update searcher"
$UpdateSearcher = $updatesession.CreateUpdateSearcher()
Write-DebugLog "Searching for updates"
$RebootRequired = Test-PendingReboot

if (((Get-WmiObject Win32_OperatingSystem).Name) -notlike "*Windows 7*") {
  $UpdateSearcher.ServiceID = '7971f918-a847-4430-9279-4a52d1efe18d' #microsoft update online
  $UpdateSearcher.SearchScope = 1 # MachineOnly
  $UpdateSearcher.ServerSelection = 3 # Windows Update (2) Third Party (3)
}
$searchresult = $updatesearcher.Search("IsInstalled=0 And DeploymentAction=*") # 0 = NotInstalled | 1 = Installed
$count = 0
$Updates = if ($searchresult.Updates.Count -gt 0) {
  #Updates are  waiting to be installed
  #Cache the  count to make the For loop run faster
  $count = $searchresult.Updates.Count
  Write-DebugLog "$count Updates have been found"
  Write-Verbose "Found $Count update\s!"
  Write-DebugLog "Looping through updates to retrieve information"
  for ($i = 0; $i -lt $Count; $i++) {
    #Create  object holding update
    $Update = $searchresult.Updates.Item($i)
    [pscustomobject]@{
      Title = $Update.Title
      KB = $($Update.KBArticleIDs)
      SecurityBulletin = $($Update.SecurityBulletinIDs)
      MsrcSeverity = $Update.MsrcSeverity
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
    $downloaded = $wUpdate.IsDownloaded
	$IsHidden = $wUpdate.IsHidden
	$RebootRequired  = $wUpdate.RebootRequired
    $title = $wUpdate.Title
    if ($Severity -eq "Critical" -and -not $IsHidden) {
      if ($patchDate -lt $dateLimit) {
        $colour = Set-Colour $colour "red"
      } else {
        $colour = Set-Colour $colour "yellow"
      }
      $criticalCount = $criticalCount + 1
      $criticalOutput = $criticalOutput + "<tr><td style=`"colour:red;`">$Severity</td><td>$patchAge</td><td><a href=`"https://technet.microsoft.com/en-us/library/security/$bulletin.aspx`" target=`"_blank`">$Bulletin</a></td><td><a href=`"https://support.microsoft.com/en-us/kb/$KB`" target=`"_blank`">$KB</a></td><td>$Downloaded</td><td>$IsHidden</td><td>$RebootRequired</td><td>$Title</td></tr>`r`n"
    } elseif ($Severity -eq "Moderate" -or $Severity -eq "Important" -and -not $IsHidden) {
      $colour = Set-Colour $colour "yellow"
      $moderateCount = $moderateCount + 1
      $moderateOutput = $moderateOutput + "<tr><td style=`"colour:yellow;`">$Severity</td><td>$patchAge</td><td><a href=`"https://technet.microsoft.com/en-us/library/security/$bulletin.aspx`" target=`"_blank`">$Bulletin</a></td><td><a href=`"https://support.microsoft.com/en-us/kb/$KB`" target=`"_blank`">$KB</a></td><td>$Downloaded</td><td>$RebootRequired</td><td>$IsHidden</td><td>$Title</td></tr>`r`n"
	} else {
      $otherCount = $otherCount + 1
      $otherOutput = $otherOutput + "<tr><td>Other</td><td>$patchAge</td><td><a href=`"https://technet.microsoft.com/en-us/library/security/$bulletin.aspx`" target=`"_blank`">$Bulletin</a></td><td><a href=`"https://support.microsoft.com/en-us/kb/$KB`" target=`"_blank`">$KB</a></td><td>$Downloaded</td><td>$IsHidden</td><td>$RebootRequired</td><td>$Title</td></tr>`r`n"
    }
  }
  if ($criticalCount -eq 0) {
    Write-DebugLog "No critical updates"
  }
} else {
  Write-DebugLog "No updates found"
  $colour = "green"
}

if ($RebootRequired) {
  $colour = Set-Colour $colour "yellow"
}

Write-DebugLog "Get hostname"
$fqdnHostname = [System.Net.DNS]::GetHostByName('').HostName.ToLower()
Write-DebugLog "Get current date"
$dateString = Get-Date -Format "MM-dd-yyyy HH:mm:ss"
$outputText = $outputText + "$colour+12h $dateString [$fqdnHostname]`r`n"
$outputText = $outputText + "<h2>Windows Update Check</h2>`r`n"
$outputText = $outputText + "Globally critical after number of days: $dayLimit `r`n" 
$outputText = $outputText + "&$colour Windows Updates available: $count`r`n"

if ($criticalCount -gt 0) {
  Write-DebugLog "Red colour due to critical updates"
  $outputText = $outputText + "&red Critical Windows Updates available: $criticalCount `r`n"
}
if ($moderateCount -gt 0) {
  Write-DebugLog "Yellow colour due to moderate updates"
  $outputText = $outputText + "&yellow Moderate Windows Updates available: $moderateCount`r`n"
}
if ($otherCount -gt 0) {
  Write-DebugLog "Green colour due to other updates"
  $outputText = $outputText + "&green Other Windows Updates available: $otherCount`r`n"
}
if ($RebootRequired) {
  $outputText = $outputText + "&yellow Reboot required after previous installs`r`n"
}
if ($count -gt 0) {
  Write-DebugLog "Updates have been detected so output contains updates listing"
  $outputText = $outputText + "<p>&nbsp;</p>`r`n"
  $outputText = $outputText + "<style>table.updates, table.updates th, table.updates td {border: 1px solid silver; border-collapse:collapse; padding:5px; background-color:black;}</style>`r`n"
  $outputText = $outputText + "<table class=`"updates`"><tr><th>Severity</th><th>Age (days)</th><th>Bulletin</th><th>KB</th><th>Downloaded</th><th>Hidden</th><th>RebootRequired</th><th>Title</th></tr>`r`n"
  $outputText = $outputText + $criticalOutput
  $outputText = $outputText + $moderateOutput
  $outputText = $outputText + $otherOutput
  $outputText = $outputText + "</table>`r`n"
}

Write-DebugLog "Save contents into tmp file"
$outputText | Set-Content $outputFile
