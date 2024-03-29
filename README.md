# Xymon powershell client with Windows updates centrally managed 
![image](https://user-images.githubusercontent.com/8841264/199198419-4cd07376-f364-4962-8ad4-9911e1c553a7.png)

## Content
- A working procedure to have Xymon monitoring with the powershell client and a **Windows Updates extension script** 
- Tested so far with Windows 2016, Windows 2019, Windows 10, Windows 11

## Prerequisit 1: The powershell client (agent)
- https://sourceforge.net/p/xymon/code/HEAD/tree/sandbox/WinPSClient/ 
- Installed by following the doc: https://sourceforge.net/p/xymon/code/HEAD/tree/sandbox/WinPSClient/XymonPSClient.doc?format=raw (but you probably do not need it)
    - The powershell agent installation steps: Open cmd prompt as admin 
        ```
        mkdir "c:\Program Files\xymon"
        mkdir "c:\Program Files\xymon\ext"
        mkdir "c:\Program Files\xymon\tmp"
        ```
        
    - Review xymonclient_config.xml and at the least, set the Xymon server address.
    - Copy the following files to a directory on the target server (e.g. c:\program files\xymon) 
        - xymonclient.ps1
        - nssm.exe
        - xymonclient_config.xml
    -	Run the following command to install the service from a PowerShell prompt (may need to be an administrative prompt):
        ```
        powershell -executionpolicy unrestricted -File "c:\Program Files\xymon\xymonclient.ps1" install
        powershell -executionpolicy unrestricted -File "c:\Program Files\xymon\xymonclient.ps1" start
        ```

Remarks
- You have now a service called XymonPSClient: You can restart it to trigger the script and see the result in Xymon
- my Xymonclient_config.xml:

    ```
    <XymonSettings>
            <servers>xymon.domain.tld</servers>
            <clientlogfile>c:\program files\xymon\xymonclient.log</clientlogfile>
            <clientconfigfile>c:\program files\xymon\clientconfig.cfg</clientconfigfile>
            <clientfqdn>1</clientfqdn>
            <clientlower>0</clientlower>
            <wanteddisks>2 3 4</wanteddisks>
            <clientremotecfgexec>1</clientremotecfgexec>
            <externalscriptlocation>c:\program files\xymon\ext</externalscriptlocation>
            <externaldatalocation>c:\program files\xymon\tmp</externaldatalocation>
            <XymonAcceptUTF8>1</XymonAcceptUTF8>
            <clientbbwinmembug>0</clientbbwinmembug>
    </XymonSettings>
    ```

- Change the server's name with yours!  
- I use only fqdn: my client also! 
- If you download the files through internet, they can be blocked (right click on the files, properties, unblock and apply)
- If you need to edit them, use notepad as admin and use "save as"
- Control that your files are in ANSI and not in UTF8 (Use notepad "save as" to verify that the encoding is ANSI and not UTF8: notepad detect if there are UTF8 char automatically: so look at the proposed encoding type)

## The Xymon config in Central Mode
This explains how to have
- A centrally managed powershell client
- A centrally managed repository for all the external scripts

The powershell client announce itself to the Xymon server by default as 
- Class : powershell
- OS    : powershell

Configuration:
- In etc/analysis.cfg, at the end, but before the DEFAULT section 
    ```
    CLASS=powershell
            LOAD 50 80
            LOG %.*  %^error.* COLOR=red #IGNORE=TermServDevices \(
            LOG %.*  %^warning.* COLOR=yellow IGNORE=%.*TermServDevices.*
            LOG %.*  %^failure.* COLOR=yellow
    ```
- In etc/xymonserver.cfg, increase the message size (not sure it is really needed but seems a good value)
    ```
    MAXMSG_CLIENT=1024              # clientdata messages (default=512k)
    ```
- In "download", put the updates.ps1 script     
    ```
    wget https://raw.githubusercontent.com/bonomani/Xymon-powershell-client-with-Windows-updates-centrally-managed/main/updates.ps1
    md5sum ./updates.ps1
    ```
- In etc/client-local.cfg: replace the hash with the md5 just done above
    ```
    [powershell]
    clientversion:2.42:https://x.x.x.x/xymon/download/ 
    external:everyscan:async:bb://updates.ps1|MD5|016e2f3725f-hash-to-be-replaced-a85ebe267b3d83|powershell.exe|-executionpolicy remotesigned -file "{script}"
    xymonlogsend
    ```
- restart xymon
- Optionally, if you dont want that this error propagate: In etc/hosts: 
    ```
    10.0.0.1              myserver.domain.tld                 # nopropyellow:updates nopropred:updates
    ```
Remarks
- In etc/analysis.cfg. I did configured the LOAD to have something better than the default values! (I do not know if the LOG entries are really useful, see above)
- In etc/client-local.cfg you need at least the [powershell] section (can be empty), otherwise the CLASS=powershell in etc/analysis.cfg seems not to work??? (The [powershell] section does not exist at all... so you will have to create it first! But it could/should exist as a default empty section in the client-local.cfg (Xymon Bug?)
- the clientversion is not tested by me so far, but should do the equivalent as using the bb protocol but secured! (so this is the best option):  We should be able to replace "bb" by "https://x.x.x.x/xymon/download/": both option should be valid (even with http!) and this for the Xymon client itself and external scripts as their process are both managed by the Xymon client. The hash seems more optional than for external scripts as a change is managed by the version number (but I think it is a good idea to have it also)
- The "external" line 
    - uses the native bb protocol, but you should also be able to use http (check that the updates.ps1 is not blocked if it is downloaded with http as this can be a problem/bug)
    - If Windows update is not available the process is block at least 10m (Windows update timeout) x retries (default:2) = 20Min: Need to be a slowscan and async)
- You can test your script with: powershell.exe -executionpolicy remotesigned -file "c:\program files\xymon\ext\updates.ps1"
- Check if your MD5 is correct: md5sum ./updates.ps1 and adjust it in your etc/client-local.cfg!
- Check the log file on your windows server "c:\program files\xymon\xymonclient.log", you should see that 
     - if the MD5 hash just changed in your etc/client-local.cfg (dont forget to restart xymon) the updates.ps1 script should be downloaded 
- Updates are in UTF-8, so you have to use \<XymonAcceptUTF8\>1\</XymonAcceptUTF8\> (or you should modify the script: end of it)
     - Check what you receive at the xymon server side in the folder that receive host's data: /var/lib/xymon/hostdata/ 
     - For Apache: Your webserver should also have UTF-8 configured, in /etc/apache2/conf-available/charset.conf uncomment:
          AddDefaultCharset UTF-8
- Check that your Xymon client-local.cfg are still in ansi(ascii) and not in UTF-8: 
    ```
    file -bi ./client-local.cfg
    ```  
- The "xymonlogsend" line allow to have a test/column named "xymonlog" for you windows machine that contains the "c:\program files\xymon\xymonclient.log" file
- To check that the "xymonlogsend" line is working, see the last line of the "c:\program files\xymon\xymonclient.log" file is: XymonLogSend - sending log 
- The updates.ps1 does a critical alarm only after 14 days 

## Contributions (No implemented so far)

1. Check if "ext" folder exist and if it does not, create it:
- I added this before the first Function; note that I install and run from a C:\Utils folder, not Program Files, change as needed.
     ```
     $extfilepath = 'c:\Utils\ext'
      IF(!(Test-Path $extfilepath))
      {New-Item C:\Utils\ext –Type Directory}
     ```
2. Filter patchs older that 365 days
- I also filtered the output in the ForEach loop by enclosing   
    ```
    If ($patchAge -lt 365){...}
    ```
3. Old updates
- As "cmd" admin, you can try (at your own risk, make a VM snapshot if you can!) 
- Reboot before to have a clean state
  ```
  net stop wuauserv
  net stop cryptSvc
  net stop bits
  net stop msiserver

  del /f /q “%ALLUSERSPROFILE%\Application Data\Microsoft\Network\Downloader\qmgr*.dat”
  del /f /s /q %SystemRoot%\SoftwareDistribution\*.*
  del /f /s /q %SystemRoot%\system32\catroot2\*.*
  del /f /q %SystemRoot%\WindowsUpdate.log

  net start wuauserv
  net start cryptSvc
  net start bits
  net start msiserver
  ```
4. Update registry (To configure Windows to not automatically start any update)
  ```
# Define Registry paths, key(s) and variables
#############################################
# paths
$regPathAU = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
$regPathWindowsUpdate = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate'

# key(s)/variables
$regPropertyENA = 'ElevateNonAdmins'
$desiredValueENA = '0' # ElevateNonAdmins = 0 - Only users in the Administrators user group can approve or disapprove updates
$response = ''
#############################################

#Test WU path, if path exists then create key, else create path then create key
if (Test-Path -Path $regPathWindowsUpdate) {
    Set-ItemProperty -Path $regPathWindowsUpdate -Name $regPropertyENA -Type DWord -Value $desiredValueENA -ErrorAction Stop
    $response = 'WU - ElevateNonAdmins key created.'
    Write-Output $response
} else {
    New-Item -Path $regPathWindowsUpdate -Force
        $response = 'Created Windows Update registry path.'
        Write-Output $response
    Set-ItemProperty -Path $regPathWindowsUpdate -Name $regPropertyENA -Type DWord -Value $desiredValueENA -ErrorAction Stop
    $response = 'WU - ElevateNonAdmins key created.'
    Write-Output $response
}

# Test AU path, if path exists then create keys, else create path then create keys
# NoAutoUpdate - 1 = enable Automatic Updates
# AUOptions - 3 = Automatically download and notify of installation
# AutoInstallMinorUpdates - 0 = Treat minor updates like other updates
if (Test-Path -Path $regPathAU) {
    'Name,Value,Type
    NoAutoUpdate,1,DWORD
    AUOptions,3,DWORD
    AutoInstallMinorUpdates,0,DWORD' | 
        ConvertFrom-Csv |
        Set-ItemProperty -Path $regPathAU -Name { $_.Name } 
      $response = 'AU Registry keys created.'
      Write-Output $response
    } else {
        New-Item -Path $regPathAU -Force
            $response = 'Created AU registry path.'
            Write-Output $response
        'Name,Value,Type
        NoAutoUpdate,1,DWORD
        AUOptions,3,DWORD
        AutoInstallMinorUpdates,0,DWORD' | 
            ConvertFrom-Csv |
            Set-ItemProperty -Path $regPathAU -Name { $_.Name } 
        $response = 'AU Registry keys created.'
        Write-Output $response
    }
  ```
