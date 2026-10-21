# Tests

Static consistency tests for the Windows Customizations engine, plus the manual procedure
for validating runtime behavior on a device.

## Running the static suite

```powershell
.\Tests\Invoke-Tests.ps1            # detailed console output
.\Tests\Invoke-Tests.ps1 -CI        # also writes out\TestResults.xml and sets exit code
```

Requirements:

- **Pester 5** (`Install-Module Pester -MinimumVersion 5.0`).
- **PSScriptAnalyzer** (optional). If absent, the analyzer tests are skipped, not failed.

The suite runs anywhere - no Windows 11, elevation, or device state required.

## What the static suite covers

| Area | Checks |
|---|---|
| Catalog integrity | No duplicate names; every entry has the fields its mechanism requires; valid `Mechanism`/`Type`; `AllowedValues` is an array; every `Custom` entry has a handler case in `Functions.ps1` |
| Config <-> catalog | Every `Settings.json` selection exists in the catalog and respects `AllowedValues`; `FailureMode` and `Organization` are valid |
| Schema <-> catalog | `Settings.schema.json` has a property for every catalog entry and no orphans (run `tools\Update-SettingsSchema.ps1` if this fails) |
| Parsing | Every `.ps1`/`.psm1`/`.psd1` parses without errors |
| Function library | `Functions.ps1` dot-sources cleanly and defines its public functions; the log folder follows the deployment channel (task sequence / ConfigMgr client / Intune); WinPE and task sequence detection |
| Detection script | The not-detected path exits `0` with no output (the contract Intune and ConfigMgr share) |
| Encoding & style | No BOM; CRLF line endings; no trailing whitespace; PowerShell source is ASCII-only |
| PSScriptAnalyzer | No Error findings; warnings limited to a known-deliberate allowlist |

## What the static suite does NOT cover

Runtime behavior touches the live Default User hive, removes provisioned apps, replaces
protected system files, and runs DISM. **Never run the engine on a workstation you care
about.** Validate it on a throwaway VM or a wipe-and-reload test device.

### Manual device test procedure

1. **Prepare a clean Windows 11 VM/device** matching your target edition/build. Snapshot it.
2. **Stage the package and assets.** Copy the repo (with captured `package\Assets\`) to the device,
   e.g. `C:\WC`.
3. **Run the engine as SYSTEM** (mimics the IME or a task sequence step):
   ```
   psexec -s -i powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\WC\package\Set-WindowsCustomizations.ps1
   ```
   (`PsExec -s` from Sysinternals runs as SYSTEM, like the Intune Management Extension.)
4. **Check the log:**
   `%ProgramData%\Microsoft\IntuneManagementExtension\Logs\Set-WindowsCustomizations.log` -
   confirm each setting reports `Applied` and the end summary shows `0 failed`. (That is the
   folder on a test device with neither the IME nor a ConfigMgr client. With only a ConfigMgr
   client it is `%WINDIR%\CCM\Logs`.)
5. **Verify the version stamp:** `HKLM\SOFTWARE\<Organization>\WindowsCustomizations` has the
   expected `Version`, and `tools\Detect-WindowsCustomizations.ps1` (with the version
   stamped in by the build) returns detected.
6. **Create a NEW local user and sign in.** Confirm the seeded defaults applied: taskbar,
   Start, desktop icons, theme, default apps, wallpaper/lock screen.
7. **Confirm changeability:** as that standard (non-admin) user, change several of the
   applied settings (search box, taskbar alignment, file extensions) and confirm Windows
   lets you - that is the core guarantee. The locking (Policy) settings, if enabled, should
   be greyed out; everything else should be editable.
8. **Test uninstall:** run `C:\WC\package\Remove-WindowsCustomizations.ps1` as SYSTEM; confirm the version
   stamp is removed and detection now returns not-detected.
9. **Revert the snapshot** between iterations for a clean baseline.

### Configuration Manager task sequence check

Run this when the ConfigMgr path changes. It needs a lab site and a test task sequence.

1. Build with `.\tools\New-Package.ps1 -Target ConfigMgr` and create the package per
   [docs/ConfigMgr.md](../docs/ConfigMgr.md) §3.
2. Add the Run Command Line step after *Setup Windows and ConfigMgr* and image a test VM.
3. In `smsts.log`, confirm the step exited `0` and its output shows the engine's lines, including
   `Running in a Configuration Manager task sequence`.
4. Confirm `Set-WindowsCustomizations.log` sits with the task sequence logs
   (`%WINDIR%\CCM\Logs` after the task sequence ends).
5. Continue with steps 5-7 above (version stamp, new user, changeability).
6. Optional negative check: put a copy of the step in the WinPE phase (the boot image needs
   PowerShell support). It must fail with `Running in WinPE` in the log.
