# Xymon powershell client with Windows updates centrally managed 
![image](https://user-images.githubusercontent.com/8841264/196809858-d9535457-b7f6-4bf4-8e0d-b0550066b004.png)

This is a working procedure to have Xymon monitoring with Windows Updates 
- with the installation of the "powershell" client
- Tested so far with Windows 2016
- No "Feature updates" (Version upgrade like going to version 22h2 in Windows 10)
    - Only applicable to Windows "Desktop": There are no "Feature update" for Windows Server 
    - Could be obtain probably by comparing the current version number and Windows Online (how??) 

## Prerequisit 1: The powershell client (agent)
- https://sourceforge.net/p/xymon/code/HEAD/tree/sandbox/WinPSClient/ 
- Installed by following the doc: https://sourceforge.net/p/xymon/code/HEAD/tree/sandbox/WinPSClient/XymonPSClient.doc?format=raw
    - The powershell agent installation steps: Open cmd prompt as admin 
        ```
        mkdir "c:\Program Files\xymon"
        ```
        
    - Review xymonclient_config.xml and at the least, set the Xymon server address.
    - Copy the following files to a directory on the target server (e.g. c:\program files\xymon) 
        - xymonclient.ps1
        - nssm.exe
        - xymonclient_config.xml
    -	Run the following command to install the service from a PowerShell prompt (may need to be an administrative prompt):
        ```
        cd "c:\Program Files\xymon\"
        powershell
        .\xymonclient.ps1 install
        .\xymonclient.ps1 start
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
    </XymonSettings>
    ```

- Change the server's name with yours!  
- I use only fqdn: my client also! 
- We need 2 extra folders:

    ```
    mkdir "c:\Program Files\xymon\ext"
    mkdir "c:\Program Files\xymon\tmp"
    ```

- If you download the files through internet, they can be blocked (This is explain in XymonPSClient.doc)
- If you need to edit them, use notepad as admin and use "save as"
- Control that your files are in ANSI and not in UTF8 (Use notepad "save as" to verify that the encoding is ANSI and not UTF8: notepad detect if there are UTF8 char automatically: so look at the proposed encoding type)

## The Xymon config in Central Mode
This explains how to have
- A centrally managed powershell client
- A centrally managed repository for all the external scripts

The powershell client announce itself by default as 
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
- In etc/client-local.cfg
    ```
    [powershell]
    clientversion:2.42:https://x.x.x.x/xymon/download/ 
    external:everyscan:sync:bb://updates.ps1|MD5|016e2f3725f2571698a85ebe267b3d83|powershell.exe|-executionpolicy remotesigned -file "{script}"
    xymonlogsend
    ```
- restart xymon
- In "download", put the updates.ps1 script
- In etc/xymonserver.cfg, increase the message size: MAXMSG_CLIENT=1024              # clientdata messages (default=512k)
- (optional) In etc/hosts: 10.0.0.1              myserver.domain.tld                 # nopropyellow:updates nopropred:updates

Remarks
- In etc/analysis.cfg. I did configured the LOAD to have something better than the default values! (I dont know if the rest is really working)
- In etc/client-local.cfg you need at least the [powershell] section (can be empty), otherwise the CLASS=powershell in etc/analysis.cfg seems not to work??? (The [powershell] section does not exist at all... so you will have to create it first! But it could/should exist as a default empty section in the client-local.cfg (Xymon Bug?)
- the clientversion is not tested by me so far, but should do the equivalent as using the bb protocol but secured! (so this is the best option):  We should be able to replace "bb" by "https://x.x.x.x/xymon/download/": both option should be valid (even with http!) and this for the Xymon client itself and external scripts as their process are both managed by the Xymon client. The hash seems more optional than for external scripts as a change is managed by the version number (but I think it is a good idea to have it also)
- The "external" line 
    - uses the native bb protocol, but you should also be able to use http (check that the updates.ps1 is not blocked if it is downloaded with http as this can be a problem/bug)
    - is not optimized by now: could be slowscan (and async?)
- You can test your script with: powershell.exe -executionpolicy remotesigned -file "c:\program files\xymon\ext\updates.ps1"
- Check if your MD5 is correct: md5sum ./updates.ps1 and adjust it in your etc/client-local.cfg!
- Check the log file on your windows server "c:\program files\xymon\xymonclient.log", you should see that 
     - if the MD5 hash just changed in your etc/client-local.cfg (dont forget to restart xymon) the updates.ps1 script should be downloaded 
     - there are no special chars (UTF 8 Problem: there is an option to use UTF8, but it seems safer to stay in ASCII)
- Check that your Xymon client-local.cfg are still in ansi(ascii) and not in UTF8: 
    ```
    file -bi ./client-local.cfg
    ```  
- The "xymonlogsend" line allow to have a test/column named "xymonlog" for you windows machine that contains the "c:\program files\xymon\xymonclient.log" file
- To check that the "xymonlogsend" line is working, see the last line of the "c:\program files\xymon\xymonclient.log" file is: XymonLogSend - sending log 
- The updates.ps1 does a critical alarm only after 14 days (could be written somewhere)
- Optionnally, as I do not want to have alarms for this test on my main page so I disable the alarm propagation (nopropyellow)

Contributions (No implemented so far)

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
