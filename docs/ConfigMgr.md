# Deploying with Configuration Manager

Intune with Windows Autopilot is the default way to deploy this solution (see the
[README](../README.md#quick-start)). This guide covers the supported alternative: running the
same package as a step in a Configuration Manager (ConfigMgr) task sequence. The engine,
`Settings.json`, and assets are identical for both. Only the packaging and the log location differ.

---

## 1. Supported scenario

The step must run **as SYSTEM, in the full OS, before any user signs in**. That is what the
Autopilot device ESP provides, and a task sequence that lays down a fresh OS provides it too:

| Task sequence | Supported? |
|---|---|
| Bare metal / new computer | ✅ Yes |
| Wipe-and-load (refresh) without restoring user state | ✅ Yes |
| Wipe-and-load with USMT user-state restore | ⚠️ Machine-level settings apply; **restored profiles do not get the Default User seeds**, only users who sign in for the first time do |
| In-place upgrade | ⚠️ Same as above: existing profiles keep their own settings |
| Application deployed to a collection of in-service devices | ❌ Not supported. Settings reach only new profiles, and the debloat items (app removal, `RemoveOfficeApps`) act on a device that is already in use |

Profiles that already exist when the engine runs never pick up the Default User hive seeds. See
[Design.md §6](Design.md#6-default-user-hive-seeding).

---

## 2. Build the content

```powershell
.\tools\New-Package.ps1 -Target ConfigMgr
```

This needs no Content Prep Tool. It writes two things to `out\`:

- `out\ConfigMgr\<version>\`: a copy of `package\` with your `Settings.json` and captured
  assets. This is the content source. Copy it to your source share, in a new folder for
  each version.
- `out\Detect-WindowsCustomizations.<version>.ps1`: the detection script. You only need it for
  the application model (§4).

---

## 3. Package and task sequence step (recommended)

1. Create a **package** from the content source, with no program, and distribute it to your
   distribution points.
2. Add a **Run Command Line** step to the task sequence:

   | Setting | Value |
   |---|---|
   | Command line | `powershell.exe -NoProfile -ExecutionPolicy Bypass -File Set-WindowsCustomizations.ps1` |
   | Package | The package from step 1 |
   | Disable 64-bit file system redirection | Not needed: the script relaunches itself as 64-bit |
   | Success codes | `0` (the default `0 3010` is fine) |

   A **Run PowerShell Script** step also works: pick the package, set the script name to
   `Set-WindowsCustomizations.ps1`, and set the execution policy to **Bypass**.

### Where the step goes

- **After Setup Windows and ConfigMgr.** Every handler acts on the running OS (DISM and Appx
  `-Online`, `C:\Users\Default`). In WinPE the engine logs an error and exits `1`, failing the step,
  rather than changing WinPE.
- **Before the Microsoft 365 Apps install, if `RemoveOfficeApps` is enabled.** That setting
  uninstalls every Click-to-Run product whose name starts with `Microsoft 365 -` or
  `Microsoft OneNote -`, and that includes Microsoft 365 Apps for enterprise. It exists to remove
  OEM-preinstalled stubs. An image built from Microsoft media has none, so you can also just
  leave it off.
- **Mind other steps that edit the Default User profile.** If two steps set the same value, the
  later one wins. A step that leaves `C:\Users\Default\NTUSER.DAT` loaded makes this step's hive
  load fail, so each step must unload it.
- Apps referenced by the taskbar or Start layout can be installed before or after this step.
  Pins resolve at first sign-in, which comes after the task sequence ends.

---

## 4. Application instead of a package (optional)

Use this if you prefer the application model and an **Install Application** step.

| Setting | Value |
|---|---|
| Deployment type | Script Installer, content = the content source |
| Install program | `powershell.exe -NoProfile -ExecutionPolicy Bypass -File Set-WindowsCustomizations.ps1` |
| Uninstall program | `powershell.exe -NoProfile -ExecutionPolicy Bypass -File Remove-WindowsCustomizations.ps1` |
| Detection method | Custom script, PowerShell: `out\Detect-WindowsCustomizations.<version>.ps1` |
| User experience | Install for system, whether or not a user is logged on |

On the application's **General Information** tab, enable **Allow this application to be installed
from the Install Application task sequence action without being deployed**. Then don't deploy it to
collections: the task sequence is what limits it to new OS installs (see §1).

The detection script is the same one Intune uses. It follows the contract both products share:
exit `0` with output means detected, and exit `0` with no output means not detected. ConfigMgr
treats a non-zero exit as a failed detection script, not as "not installed".

---

## 5. Exit codes

| Exit | Meaning |
|---|---|
| `0` | Success. Under `FailureMode` **Lenient** (the default), individual settings that fail are logged and still exit `0`. Also returned on a non-Windows 11 OS, where nothing is done |
| `1` | `Settings.json` is missing or invalid, the Default User hive can't be loaded, the step ran in WinPE, or (with `FailureMode` **Strict**) any setting failed |

A non-zero exit fails the step, which stops the task sequence unless the step has
**Continue on error** set.

---

## 6. Logs

The engine writes a CMTrace-format log and picks the folder from where it runs:

| Run from | Log folder |
|---|---|
| A task sequence step | `_SMSTSLogPath`, next to `smsts.log`, so it travels with the task sequence logs. After the task sequence ends, look wherever your `smsts.log` ended up (normally `%WINDIR%\CCM\Logs`) |
| An application install on a device with the ConfigMgr client but no Intune Management Extension, when the task sequence environment can't be read | `%WINDIR%\CCM\Logs` |
| Intune (the default) | `%ProgramData%\Microsoft\IntuneManagementExtension\Logs` |

The file is `Set-WindowsCustomizations.log` (`Remove-WindowsCustomizations.log` for an uninstall).
A task sequence step's console output, including every log line, also appears in `smsts.log`.

---

## 7. What's different without Intune

- **Start pins:** the `ConfigureStartPins` JSON ([Asset-Preparation.md §2](Asset-Preparation.md#2-start-menu-layout),
  Method B) works only through MDM. On devices that are not enrolled in Intune (not co-managed),
  use the `start2.bin` seed (Method A) that this package applies.
- **Version stamp:** the engine still writes `HKLM\SOFTWARE\<Organization>\WindowsCustomizations`
  (`Version`, `InstalledOn`) on success. You can use it for reporting.
