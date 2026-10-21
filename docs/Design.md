# Windows Customizations — Design

Architecture of record for the modernized solution. Companion to
[Customizations.md](Customizations.md) (the *what*) and
[Asset-Preparation.md](Asset-Preparation.md) (how end users capture the asset files).

---

## 1. Overview

A Win32 app (`.intunewin`) assigned to **devices** and run during Windows Autopilot
(as SYSTEM, in the device ESP phase) that applies Windows 11 customizations as
**user-changeable defaults**. The engine is **data-driven**: a code-owned catalog
describes every customization; a per-deployment JSON config selects values; a small
generic applier walks the catalog and dispatches to mechanism handlers.

Intune/Autopilot is the default deployment channel. The same package is also supported as a
**Configuration Manager task sequence step** in the full OS ([ConfigMgr.md](ConfigMgr.md)). The
engine doesn't depend on the channel: only the packaging (§9) and the log folder (§7) differ.

Design principles:

- **Changeable-first.** Default to per-user defaults (Default User hive / seed files) that a
  non-admin can change. Only lock a setting (GP policy) when explicitly intended.
- **Data over code.** Adding a customization is a catalog edit, not an engine edit.
- **Idempotent.** Re-running produces the same end state; safe for ESP or task sequence retries
  and version bumps.
- **5.1-compatible.** Runs under Windows PowerShell 5.1, started by the Intune Management
  Extension or a task sequence step.

---

## 2. Execution flow

```
Intune Management Extension (32-bit, SYSTEM)  — or a ConfigMgr task sequence step (SYSTEM)
  └─ powershell.exe -NoProfile -ExecutionPolicy Bypass -File Set-WindowsCustomizations.ps1
       1. Re-launch under SysNative (64-bit) if running 32-bit
       2. Initialize logging (CMTrace; the folder follows the channel, §7)
       3. Refuse to run in WinPE (log + exit 1)
       4. Confirm OS is Windows 11 (else log + exit)
       5. Load + validate package\Config\Settings.json (against the catalog)
       6. Import package\Engine\Catalog.psd1
       7. Machine-level pass (⚙️, no Default User hive): app removal, DISM associations,
          HKLM/Policy keys, file seeds (taskbar LayoutModification.xml, Start start2.bin),
          branding file replacements, and other machine-context Custom handlers
       8. Default User hive pass (✅): reg load NTUSER.DAT → apply the hive-backed items
          (DefaultHive + hive-writing Custom handlers) → unload (GC+retry)
       9. Write version stamp on success (HKLM\SOFTWARE\<Org>\WindowsCustomizations)
      10. Emit per-setting summary; choose exit code per FailureMode
```

---

## 3. The catalog (`package\Engine\Catalog.psd1`)

The catalog is an array of **customization definition** objects. One object fully describes a
customization: its mechanism, target, valid values, default, and documentation. The config
file only *selects values* by `Name`.

### 3.1 Definition schema

| Field | Required | Notes |
|---|---|---|
| `Name` | yes | Unique key; matches the config `Customizations` key |
| `Category` | yes | Taskbar / Start / Explorer / Debloat / DefaultApps / System / Accessibility / Branding |
| `Description` | yes | Human-readable; also documents valid values |
| `Mechanism` | yes | `DefaultHive` \| `HKLM` \| `Policy` \| `File` \| `AppRemoval` \| `Dism` \| `Custom` |
| `Path` | reg mechs | Registry subpath (rooted at the loaded hive for `DefaultHive`, at `HKLM:` for `HKLM`/`Policy`) |
| `ValueName` | reg mechs | Registry value name |
| `Type` | reg mechs | `DWord` \| `String` \| `ExpandString` \| `QWord` \| `MultiString` \| `Binary` |
| `AllowedValues` | optional | Whitelist; applier rejects out-of-range config values |
| `NeedsHive` | `Custom` | `$true` when the bespoke logic writes into the Default User hive, so the applier mounts it for the handler |
| `Source` / `Destination` | `File` | Asset path (under `package\Assets`) and target path |
| `Source` / `Operation` | `Dism` | Asset path and the DISM operation identifier the handler runs |
| `AssetRoot` | `File` / `Dism` | Expected XML root element; the configurator uses it to validate a browsed asset |
| `PackageNames` / `AvailablePackages` | `AppRemoval` | Default removal list and the full selectable menu (config may override with an array) |
| `DependsOn` | optional | `Name` of a prerequisite entry that must be enabled first |

A `Policy` mechanism is what *locks* a setting; the config/UX warns on it by checking `Mechanism`
directly (there is no separate `Locks` field). `Custom` entries have no handler field either —
`Invoke-CustomHandler` dispatches on `Name`, so each `Custom` entry has a matching case in
`Functions.ps1`.

### 3.2 Example entries

```powershell
@{
    Name          = 'TaskbarAlignment'
    Category      = 'Taskbar'
    Description   = 'Taskbar alignment: 0 = left, 1 = center'
    Mechanism     = 'DefaultHive'
    Path          = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
    ValueName     = 'TaskbarAl'
    Type          = 'DWord'
    AllowedValues = @(0, 1)
},
@{
    Name          = 'EdgeFirstRun'
    Category      = 'Debloat'
    Description   = 'Suppress Edge first-run experience (LOCKS the setting)'
    Mechanism     = 'Policy'      # Policy mechanism locks the setting
    Path          = 'SOFTWARE\Policies\Microsoft\Edge'
    ValueName     = 'HideFirstRunExperience'
    Type          = 'DWord'
    AllowedValues = @(1)
},
@{
    Name          = 'RemoveProvisionedApps'
    Category      = 'Debloat'
    Description   = 'Remove provisioned UWP apps (config may override the list)'
    Mechanism     = 'AppRemoval'
    PackageNames  = @('Microsoft.BingNews', 'Microsoft.GamingApp', 'Microsoft.GetHelp')
}
```

---

## 4. Config (`package\Config\Settings.json`)

The hand-edited, per-deployment file. A companion `Settings.schema.json` provides VS Code
validation/autocomplete. A customization **omitted** from `Customizations` is *not
configured* (skipped) — the modern equivalent of commenting out an ini line.

```jsonc
{
    "$schema": "./Settings.schema.json",
    "Organization": "Contoso",
    "FailureMode": "Lenient",        // Lenient | Strict
    "Customizations": {
        "SearchBoxMode": 1,
        "TaskbarAlignment": 0,
        "Widgets": 0,
        "ShowFileExtensions": 1,
        "RemoveProvisionedApps": ["Microsoft.BingNews", "Microsoft.GamingApp"],
        "EdgeFirstRun": 1            // schema flags this as a locking setting
    }
}
```

The applier validates each entry: the `Name` must exist in the catalog, and the value must
satisfy `AllowedValues`/`Type`. Invalid entries are reported up front (fail-fast on config),
distinct from per-setting runtime failures (governed by `FailureMode`).

---

## 5. Mechanism handlers (`package\Engine\Functions.ps1`)

The engine's functions live in a single library, `package\Engine\Functions.ps1`, **dot-sourced**
(not imported as a module) by both `Set-WindowsCustomizations.ps1` and
`Remove-WindowsCustomizations.ps1` so every function shares one scope. (Cross-importing
`.psm1` modules was rejected: a module's internal `Import-Module -Force` pulls its
dependency out of the caller's scope, and module functions can't see the caller's scope -
either way the entry script loses access to the logging/registry helpers.)

`Invoke-Customization` dispatches each item to its mechanism handler and wraps the outcome in a
uniform result object, so the applier stays generic:

```
Invoke-Customization -Definition <catalog object> -Value <desired value> [-HiveDrive <PSDrive>]
    → dispatches to the mechanism handler (a throw becomes a Failed result)
    → returns [pscustomobject]@{ Name; Status; Message }   # Status: Applied | Skipped | Failed
```

| Mechanism | Handler responsibility |
|---|---|
| `DefaultHive` | Set `Path\ValueName` under the loaded default-user hive drive |
| `HKLM` | Set a non-policy machine value under `HKLM:` |
| `Policy` | Set a GP-backed value under `HKLM:` (locks; flagged) |
| `File` | Copy `Source` (under `/package/Assets`) to `Destination` (e.g. `C:\Users\Default\...`) |
| `AppRemoval` | `Get-AppxProvisionedPackage` → `Remove-AppxProvisionedPackage` for each name |
| `Dism` | DISM operations (e.g. `/Import-DefaultAppAssociations`) |
| `Custom` | Dispatch to a named function for bespoke logic |

The applier handles common concerns once (logging, try/catch per item, result collection),
so handlers stay small. `FailureMode` decides whether a `Failed` result changes the exit code.

---

## 6. Default User hive seeding

Primary mechanism for ✅ settings. Procedure:

1. `reg load HKLM\WC_DefaultUser C:\Users\Default\NTUSER.DAT`
2. `New-PSDrive` over the loaded key; apply all `DefaultHive` definitions through it.
3. Unload with the **GC-collect + retry** loop (the handle lingers briefly after `Remove-PSDrive`;
   retry up to 3× with `[gc]::Collect()` between attempts).

> **`HKCU\Software\Classes` can't be seeded directly.** It is *not* stored in `NTUSER.DAT` — it is a
> redirect to `HKEY_USERS\<SID>_Classes`, backed by the separate `UsrClass.dat` hive, which the
> Default profile does not ship. And the key must be present *before* `explorer.exe` starts, or it
> only takes effect on the **next** logon (a `RunOnce` is processed *by* explorer, so it lands too
> late). So a setting that needs a key there (e.g. `ClassicContextMenu`) installs an **HKLM Active
> Setup component** whose per-user `StubPath` (`reg add … /ve /d "" /f`) runs at first logon *before*
> the shell, writing into the user's live `HKCU\Software\Classes`. Correct on the very first logon; the
> component is machine-level so each user runs it once at their next logon and can still change it.
> Writing the key into `NTUSER.DAT\Software\Classes` directly has **no runtime effect** — a hive
> read-back appears to succeed but the user never sees it.

**File-based seeds** are the same strategy via the filesystem — copied into `C:\Users\Default`:

| Asset | Default-profile destination |
|---|---|
| Taskbar pins (`LayoutModification.xml`) | `…\Users\Default\AppData\Local\Microsoft\Windows\Shell\` |
| Start layout (`start2.bin`) | `…\Users\Default\AppData\Local\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState\` |

In device-targeted Autopilot the app runs before any profile is created, so the enrolling
user and all future users inherit these. A ConfigMgr task sequence that lays down a fresh OS
(bare metal, wipe-and-load) is the same situation, because the step runs before anyone signs in.
Profiles that **already exist** when the app runs (re-deploy, retargeting to in-service devices,
shared/multi-user machines, profiles restored by USMT or kept by an in-place upgrade) do not pick
up the hive seeds. Clean Autopilot device ESP, or a fresh-OS task sequence, is the intended
scenario.

> **Taskbar seed is only a changeable default if each pin carries `PinGeneration="N"`.** On
> 24H2/25H2 the taskbar layout is reapplied from a per-user cache (`HKCU\…\CloudStore`) on every
> `explorer.exe` restart, overwriting user pin changes — so a plain seed *locks* the pins.
> `PinGeneration` (24H2 + KB5060829 / 25H2; the taskbar analog of Start's `applyOnce`) makes a
> user-unpinned app stay unpinned. The `LayoutModification.xml` asset must include it on every pin;
> no engine change is needed. See [Asset-Preparation.md](Asset-Preparation.md) §3.
>
> **Start `start2.bin` is the only self-contained seed.** The modern `ConfigureStartPins` JSON
> (with `applyOnce`) is **MDM-only** — it's consumed solely through the PolicyManager channel, so a
> SYSTEM/Win32 registry write is never honored on a non-enrolled device. It can't replace
> `start2.bin` in this package; deliver it as a separate **Intune Settings Catalog** policy instead
> (hybrid — see Asset-Preparation.md §2, Method B). ConfigMgr-only devices (not co-managed) have no
> MDM channel, so `start2.bin` is their only option.

---

## 7. Logging, detection, failure mode

- **Logging.** CMTrace format, `Set-WindowsCustomizations.log`. Each setting logs an
  `Applied`/`Skipped`/`Failed` result; an end-of-run summary tallies counts.
  `Get-DeploymentLogDirectory` picks the folder where the deploying channel's admins look:

  | Context | Folder |
  |---|---|
  | Inside a running ConfigMgr task sequence | `_SMSTSLogPath` (next to `smsts.log`, travels with the TS logs) |
  | ConfigMgr client present, Intune Management Extension absent | `%WINDIR%\CCM\Logs` |
  | Anything else: Intune, the default | `%ProgramData%\Microsoft\IntuneManagementExtension\Logs` (collected by Intune diagnostics) |

  Outside a task sequence, the IME check makes the Intune folder win on co-managed devices, so
  the default channel's log location never moves.
- **Detection.** On success the engine writes `HKLM\SOFTWARE\<Org>\WindowsCustomizations`
  (`Version`, `InstalledOn`). The detection script (`tools\Detect-WindowsCustomizations.ps1`)
  checks the stamped `Version` against the packaged version; a version bump re-triggers on
  deployed devices. It follows the contract Intune and ConfigMgr share: exit `0` with STDOUT
  means detected, and exit `0` with no output means not detected. ConfigMgr reads a non-zero exit
  as a script failure (Unknown), so one script serves an Intune Win32 app and a ConfigMgr
  application.
- **Failure mode.** `FailureMode` (config): **Lenient** (default) logs per-setting failures and
  continues, exiting `0` unless the engine itself can't run (bad config, hive won't load);
  **Strict** returns non-zero on any `Failed` result.

---

## 8. Uninstall

`Remove-WindowsCustomizations.ps1` removes only the HKLM version stamp, which flips the detection
rule to "not installed", and returns success. It does **not** revert any customization: the Default
User hive seeds, the `ClassicContextMenu` Active Setup component, machine-level/policy registry keys,
replaced branding files, and removed apps all remain, so new users still inherit most customizations
after uninstall. Per-user values are intentionally left in place — they live in individual profiles
and are user-changeable by design. A full teardown is not implemented.

---

## 9. Packaging & build

Source layout:

```
/package       Set-WindowsCustomizations.ps1, Remove-WindowsCustomizations.ps1  (the payload)
  /Engine      Functions.ps1, Catalog.psd1, version.txt
  /Config      Settings.json, Settings.schema.json
  /Assets      /Branding, /Layout, /AppAssociations
/tools         Configure-Settings.ps1, New-Package.ps1, Update-SettingsSchema.ps1, Detect-WindowsCustomizations.ps1
/Tests         Invoke-Tests.ps1, Pester suite, device-test procedure
/docs          Customizations.md, Design.md, Asset-Preparation.md, ConfigMgr.md
/out           build output (.intunewin or ConfigMgr\<version>\ + stamped detection script); gitignored
```

- **Install command:** `powershell.exe -NoProfile -ExecutionPolicy Bypass -File Set-WindowsCustomizations.ps1`
  (the same command for an Intune Win32 app, a task sequence Run Command Line step, or a
  ConfigMgr application)
- **Uninstall command:** `powershell.exe -NoProfile -ExecutionPolicy Bypass -File Remove-WindowsCustomizations.ps1`
- **Detection rule:** custom script `tools\Detect-WindowsCustomizations.ps1`.
- **`tools\New-Package.ps1`** stamps one source-of-truth version into both the engine and the
  detection script (detection runs standalone and can't read package files at runtime). The default
  `-Target Intune` then runs `IntuneWinAppUtil` to emit the `.intunewin`; `-Target ConfigMgr` copies
  `package\` to `out\ConfigMgr\<version>\` as the content source instead. Prevents
  engine/detection version drift.

**Versioning.** Single source of truth (`package\Engine\version.txt`) consumed by the
build script; it flows into the engine's stamp and the detection script's expected value.

---

## 10. Asset dependencies

The engine ships logic; the **content** (branding images, `AppAssociations.xml`, `start2.bin`,
taskbar `LayoutModification.xml`) is captured per-org from a clean reference machine. End-user
capture instructions live in [Asset-Preparation.md](Asset-Preparation.md). Items to verify on a
current Windows 11 reference image before first release:

- Start layout filename/path (`start2.bin` vs `start.bin`) for the target build.
- The `StartMenuExperienceHost` package folder name.
- Provisioned app names in the removal list (they drift between builds).
- Taskbar `LayoutModification.xml` carries `PinGeneration="N"` on every pin (24H2/25H2), else the
  pins relock every logon (see §6 and Asset-Preparation.md §3).
- Start pins: `start2.bin` is the in-package seed; the `ConfigureStartPins` applyOnce JSON is an
  optional **Intune Settings Catalog** add-on (MDM-only), not an engine asset (Asset-Preparation.md §2).
