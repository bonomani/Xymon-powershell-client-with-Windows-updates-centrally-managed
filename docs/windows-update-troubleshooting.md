# Windows Update troubleshooting

When the script reports `Update unreachable` or `Last probe online: n/a`,
the underlying Windows Update Agent is failing - the script itself just
relays that state. The procedure below covers the standard order to
diagnose and repair WUA without breaking it. Sources: Microsoft
KB947821 ([Fix Windows Update errors](https://learn.microsoft.com/en-us/troubleshoot/windows-server/installing-updates-features-roles/fix-windows-update-errors))
and the [WinSxS cleanup guidance](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/clean-up-the-winsxs-folder).

## 1. Order of operations

```text
network / proxy check
  v (ok)
DISM /restorehealth
  v (ok)
sfc /scannow
  v (still failing)
reset WU services + folders
  v (still failing)
analyse CBS.log + Setup event log
```

The order matters: SFC repairs files by pulling clean copies from the
WinSxS component store, so the store must be healthy first. That is
what DISM `/Restorehealth` does. Running SFC before DISM is a common
mistake - Microsoft KB947821 specifies DISM first, then SFC, then
restart.

## 2. Safe commands (standard use)

### 2.1 Network / proxy check (do this first)

The most common cause of "Windows Update is unreachable" is a
misconfigured WinHTTP proxy, not corruption. WUA uses **WinHTTP**, not
WinINET / IE settings.

```cmd
netsh winhttp show proxy
```

```powershell
Test-NetConnection windowsupdate.microsoft.com -Port 443
Get-Service wuauserv,BITS,UsoSvc | Format-Table Name,Status,StartType
```

If the proxy is wrong, import the IE settings into WinHTTP:

```cmd
netsh winhttp import proxy source=ie
```

### 2.2 Component store and system files (DISM first, then SFC)

```cmd
dism /online /cleanup-image /checkhealth
dism /online /cleanup-image /scanhealth
dism /online /cleanup-image /restorehealth
sfc /scannow
```

`/CheckHealth` and `/ScanHealth` are read-only; `/RestoreHealth` repairs
from Windows Update or a local source. SFC then re-fills the protected
files from the (now healthy) store.

### 2.3 Reset Windows Update state

```cmd
net stop wuauserv
net stop bits
net stop cryptsvc

ren C:\Windows\SoftwareDistribution SoftwareDistribution.old
ren C:\Windows\System32\catroot2 catroot2.old

net start cryptsvc
net start bits
net start wuauserv
```

Renames the download cache and the signature catalog so AU regenerates
them on the next scan. No system state lost.

### 2.4 Manual install / trigger scan

```cmd
wusa.exe KBxxxx.msu
dism /online /add-package /packagepath:<cab>
usoclient.exe StartScan
```

`USOClient StartScan` is the modern equivalent of the legacy
`wuauclt /detectnow`.

### 2.5 Analyse logs

```cmd
findstr /i "error failed" C:\Windows\Logs\CBS\CBS.log
```

```powershell
Get-WinEvent -LogName Setup -MaxEvents 50
```

`CBS.log` is the source of truth for component-store events.

### 2.6 Routine WinSxS cleanup

```cmd
dism /online /cleanup-image /startcomponentcleanup
```

Drops superseded versions only, keeps PSFX rollback compatible.

## 3. Commands to use with caution

```cmd
dism /online /disable-feature /featurename:<Feature> /remove
```

Removes a feature's payload. Re-enabling requires an external source.
Can break dependent features if used carelessly.

```cmd
dism /online /remove-package /packagename:<name>
```

Documented for advanced CBS troubleshooting (Microsoft KB947821).
Windows refuses to remove protected packages (returns `0x800f0825`),
but removing a package that has dependent packages still in use can
leave the system non-patchable. Identify dependencies first with
`dism /online /get-packages /format:table`.

## 4. Commands not to run on a production host

```cmd
dism /online /cleanup-image /startcomponentcleanup /resetbase
```

Removes every superseded WinSxS version. **Irreversible** - you lose
the ability to uninstall any update from now on, and you lose the
differential ("forward delta") payloads that future cumulative updates
rely on. Microsoft documents it for image preparation, not for live
hosts.

```text
manually deleting C:\Windows\WinSxS or C:\Windows\servicing
```

Immediate corruption. Not supported. Recovery typically requires a
repair install or reimage.

## 5. Underlying principle

Windows Update relies on a complete and self-consistent WinSxS
component store. Anything that removes versions from that store
(`/ResetBase`) or deletes its contents (manual `rm`) breaks the
contract future updates rely on. The "safe" commands in section 2
never remove a version that is still referenced - they only
reorganise or replenish.
