# Windows 11 reinstall procedures

Out of scope for this Xymon monitoring script - kept here as a
quick reference for the underlying host when a Windows Update
failure cannot be resolved through the
[troubleshooting procedure](windows-update-troubleshooting.md)
and a reinstall is needed.

## 1. Repair install (in-place upgrade, recommended)

Reinstalls Windows over itself, rebuilds the WinSxS component
store, and keeps personal files and applications.

```cmd
D:\setup.exe
```

Pick **Keep personal files and apps** in the UI.

## 2. Silent in-place upgrade (CLI)

```cmd
D:\setup.exe /auto upgrade /quiet /eula accept /noreboot /copylogs %SystemDrive%\Temp
```

`/eula accept` is required for a fully silent run; without it
setup blocks on the EULA dialog even with `/quiet`. `/copylogs`
captures setup logs to a known path for post-mortem on failure.

For an interactive version that just skips the launcher banner:

```cmd
D:\setup.exe /auto upgrade
```

## 3. Clean install (bootable ISO)

```text
boot from installer
  -> delete existing partitions on the target disk
  -> install Windows
```

Wipes everything. Use only when the machine is being repurposed
or a repair install has failed to recover the state.

## 4. TPM / Secure Boot bypass

### 4.1 LabConfig registry (clean install path)

Press `Shift+F10` inside the Windows setup UI to open a command
prompt, then:

```cmd
reg add HKLM\SYSTEM\Setup\LabConfig /v BypassTPMCheck        /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\Setup\LabConfig /v BypassSecureBootCheck /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\Setup\LabConfig /v BypassRAMCheck        /t REG_DWORD /d 1 /f
```

Setup re-reads the flags and skips the matching hardware
preflight checks.

### 4.2 /product server (in-place upgrade path)

```cmd
D:\setup.exe /product server
```

Tells setup to use Server-variant compatibility checks, which
skip TPM, Secure Boot and RAM verification. The installed edition
is still the one in the ISO (typically Windows 11 Pro / Home /
Enterprise) - only the preflight is affected.

Silent variant:

```cmd
D:\setup.exe /auto upgrade /product server /quiet /eula accept /noreboot
```

### 4.3 appraiserres.dll replacement (deprecated)

Replacing or zeroing `sources\appraiserres.dll` in the install
media used to bypass the compat check on early Windows 11 builds.
It is unreliable on current builds and is superseded by
`/product server` or LabConfig.

## 5. ISO version check

```powershell
Get-ComputerInfo | Select-Object WindowsVersion, OsBuildNumber
```

The ISO version must be >= the currently installed build for an
in-place upgrade to succeed.

## 6. Decision summary

```text
repair install              fix the OS without data loss
clean install               brand-new OS, all data lost
/product server             bypass TPM/SB on an upgrade
LabConfig registry          bypass TPM/SB on a clean install
```

## Security caveats

- TPM 2.0 and Secure Boot are not optional in Microsoft's threat
  model. BitLocker key sealing, Credential Guard and HVCI rely
  on the TPM; running without it weakens those defences.
- The bypass is **not stable across major releases**. A yearly
  feature update may re-check hardware and refuse the upgrade,
  forcing you to reapply the bypass or do a clean install.
