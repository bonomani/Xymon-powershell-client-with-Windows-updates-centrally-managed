# Xymon-Windows-Updates-Powershell-External-Script

This is a working procedure to have Xymon monitoring with Windows Update (with the installation of the "powerhsell" client)
(Tested so far with Windows 2016)

## Prerequisit 1: The powershell client (agent)
- https://sourceforge.net/p/xymon/code/HEAD/tree/sandbox/WinPSClient/ 
- Installed by following the doc: https://sourceforge.net/p/xymon/code/HEAD/tree/sandbox/WinPSClient/XymonPSClient.doc?format=raw
    - The powershell agent installation steps: 
        - Review xymonclient_config.xml and at the least, set the Xymon server address.
    -	Copy the following files to a directory on the target server (e.g. c:\program files\xymon: I use exactly this!) 

        ```
        mkdir "c:\Program Files\xymon"
        ```

        - xymonclient.ps1
        - nssm.exe
        - xymonclient_config.xml
    -	Run the following command to install the service from a PowerShell prompt (may need to be an administrative prompt):
        - .\xymonclient.ps1 install
    -	Either review and start the service in Windows services control panel or run:
        - .\xymonclient.ps1 start

Remarks
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

- Change the server name with yours!  
- I use only fqdn: my client also! 
- We need 2 extra folders: Create them!

    ```
    mkdir "c:\Program Files\xymon\ext"
    mkdir "c:\Program Files\xymon\tmp"
    ```

- If you download the files through internet, they can be blocked (I did not so you should find yourself how to unblock them)
- If you need to edit them use notepad as admin and use "save as"
- Control that your files are in ANSI and not in UTF8 (Use notepad "save as" to verify that the encoding is ANSI and not UTF8)

## Prerequisit 2: My xymon config
I would like to have a "central mode" to have 
- A repository for the external script
- A centrally manage client

The powershell client announce itself as 
- Class : powershell
- OS    : powershell

Configuration:
- In etc/analysis.cfg, bat the end, but berfore the DEFAULT section (I did chekc that the LOAD section is working)
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
    external:everyscan:sync:bb://updates.ps1|MD5|ccb83cc254fbc3428932a562864ab741|powershell.exe|-executionpolicy remotesigned -file "{script}"
    xymonlogsend
    ```
- In "download", put the updates.ps1 script
- restart xymon

Remarks
- In etc/client-local.cfg you need at least the [powershell] section (can be empty), otherwise the CLASS=powershell in etc/analysis.cfg seems not to work???
- The "external" line 
    - Use the native bb protocole but should also be habe to use http (will the updates.ps1 be blocked as it is downloaded?)
    - is not optimized by now: could be slowscan (and async?)
- You can test your script with: powershell.exe -executionpolicy remotesigned -file "c:\program files\xymon\ext\updates.ps1"
- Check if your MD5 is correct: md5sum ./updates.ps1 and adjust it in your etc/client-local.cfg!
- Check the log file on your windows server "c:\program files\xymon\xymonclient.log", you should see that 
     - the MD% hash did changed (if you change it) in your etc/client-local.cfg (dont forget to restart xymon) and the updates.ps1 is downloaded 
     - the config 
- Chekc that you xymon client-local.cfg are still in ansi(ascii) and not in UTF8: 
    ```
    file -bi ./client-local.cfg
    ```  
