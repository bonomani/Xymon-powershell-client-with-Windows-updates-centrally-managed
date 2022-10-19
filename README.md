# Xymon-Windows-Updates-Powershell-External-Script

This is a working procedure to have Xymon monitoring Windows Update
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

        - Xymonclient.ps1
        - Nssm.exe
        - Xymonclient_config.xml
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

## Prerequisit 2: My xymon config
I would like to have a "central mode" to have 
- 1. A repository for the external script
- 2. A centrally manage client

The powershell client announce itself as 
- Class : powershell
- OS    : powershell

So you will have to create 
