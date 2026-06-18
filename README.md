# Windows Customizations

A Win32 app, assigned to **devices** and run during Windows Autopilot, that applies a curated
set of Windows 11 settings (taskbar, Start, Explorer, default apps, debloat, branding) as
**defaults a non-admin user can still change**.

## Why this exists

Intune Settings Catalog / CSP policies and Group Policy *lock* settings - the user can't
change them. This solution does the opposite: it seeds the **Default User registry hive**
(`C:\Users\Default\NTUSER.DAT`) and other per-user defaults, so new users inherit the
configuration but remain free to change it. Locking (Policy) mechanisms are available but
optional and off by default.

## How it works

The engine is **data-driven**. A code-owned catalog ([package/Engine/Catalog.psd1](package/Engine/Catalog.psd1))
describes every customization - its mechanism, registry target, allowed values, and docs. A
per-deployment [package/Config/Settings.json](package/Config/Settings.json) just *selects values*. A small
generic applier walks the catalog and dispatches each item to a mechanism handler
(`DefaultHive`, `HKLM`, `Policy`, `File`, `AppRemoval`, `Dism`, `Custom`).

```
Intune (device ESP, SYSTEM)
  -> Set-WindowsCustomizations.ps1
       validate config -> machine-level pass -> Default User hive pass
       -> version stamp -> CMTrace log -> exit code (per FailureMode)
```

## Repository layout

| Path | Purpose |
|---|---|
| [package/](package/) | The `.intunewin` payload (ships to the device): install/uninstall entry scripts plus the subfolders below |
| &nbsp;&nbsp;[package/Engine/](package/Engine/) | Catalog, mechanism handlers, Active Setup, logging, version |
| &nbsp;&nbsp;[package/Config/](package/Config/) | `Settings.json` selections + generated `Settings.schema.json` (VS Code validation) |
| &nbsp;&nbsp;[package/Assets/](package/Assets/) | Org-specific content: branding, layout, app associations (you capture these) |
| [tools/](tools/) | Dev/admin scripts (not shipped): `Configure-Settings.ps1`, `New-Package.ps1`, `Update-SettingsSchema.ps1`, `Detect-WindowsCustomizations.ps1` |
| [Tests/](Tests/) | Pester static suite + manual device-test procedure |
| [docs/](docs/) | Customization list, design, asset-capture guide, [verification cheatsheet](docs/Verification.md) |
| [out/](out/) | Build output (`.intunewin` + stamped detection script); gitignored |

## Quick start

1. **Configure.** Either run [tools/Configure-Settings.ps1](tools/Configure-Settings.ps1) for a
   point-and-click window that lists every available setting with its description and
   choices and writes [package/Config/Settings.json](package/Config/Settings.json) for you, or hand-edit
   [package/Config/Settings.json](package/Config/Settings.json) directly - omit a setting to leave it
   unconfigured (VS Code validates against the schema as you type). The full list of
   available settings is [docs/Customizations.md](docs/Customizations.md).
2. **Capture assets.** For branding, default app associations, and Start/taskbar layout,
   follow [docs/Asset-Preparation.md](docs/Asset-Preparation.md) and drop the files into
   [package/Assets/](package/Assets/). Skip this for any feature you haven't enabled. For the app-associations
   and Start/taskbar-layout files, [tools/Configure-Settings.ps1](tools/Configure-Settings.ps1) has a
   **Browse…** button that validates the file and copies it into the right place for you.
3. **Test.** Run `.\Tests\Invoke-Tests.ps1` (static checks), then validate on a throwaway
   Windows 11 VM per [Tests/README.md](Tests/README.md).
4. **Build.** `.\tools\New-Package.ps1 -ContentPrepToolPath <path to IntuneWinAppUtil.exe>`
   produces the `.intunewin` and a version-stamped detection script in `out\`.
5. **Deploy.** Create an Intune Win32 app:
   - Install: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File Set-WindowsCustomizations.ps1`
   - Uninstall: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File Remove-WindowsCustomizations.ps1`
   - Detection: the custom script emitted by the build
   - Assign to **devices** (runs in the Autopilot device ESP).

## Documentation

- [docs/Customizations.md](docs/Customizations.md) - the target customization list (what, and which mechanism)
- [docs/Design.md](docs/Design.md) - architecture of record (engine, config, packaging)
- [docs/Asset-Preparation.md](docs/Asset-Preparation.md) - capturing branding / app associations / layout
- [Tests/README.md](Tests/README.md) - running the tests and the manual device procedure

## Requirements

- Target: **Windows 11** (Windows 10 reached end-of-support in October 2025).
- Engine runs under the Intune Management Extension's **Windows PowerShell 5.1**; the script
  re-launches itself 64-bit.
- Build/test tooling: **Pester 5**, optional **PSScriptAnalyzer**, and the Microsoft
  [Win32 Content Prep Tool](https://github.com/microsoft/Microsoft-Win32-Content-Prep-Tool).
