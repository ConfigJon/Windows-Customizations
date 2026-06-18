# Windows Customizations — Target Customization List

Living specification for the modernized Windows-Customizations solution. This is the
**what** (the customizations the solution applies); the **how** (engine architecture,
packaging, Default User hive seeding) is covered in the design phase.

## Goals & scope

- **Deliverable:** a Win32 app (`.intunewin`) assigned to **devices**, run during Windows
  Autopilot deployment (as SYSTEM, during the ESP device phase).
- **Core constraint:** every setting is applied as a **default that a non-admin user can
  still change**. Intune Settings-Catalog/CSP policies and most `HKLM\...\Policies\...`
  keys are avoided because they grey out / lock the control. The primary mechanism is
  seeding the **Default User hive** (`C:\Users\Default\NTUSER.DAT`) and other per-user
  default locations.
- **OS scope:** **Windows 11 only.** Windows 10 reached end-of-support in October 2025; no
  Win10 code paths.
- **Posture:** modernize + expand — keep relevant settings, drop obsolete ones, add modern
  items.

## Mechanism legend

| Symbol | Meaning |
|---|---|
| ✅ | Changeable default — Default User hive (HKCU) or per-user default file. User can change afterward. **Preferred.** |
| 🔒 | Locks the setting (GP-backed policy). Use only when locking is intended. |
| ⚙️ | Machine-level action — no per-user lock concern (file replacement, app removal, HKLM non-policy). |

**Design rule:** default to ✅. Only use 🔒 where a changeable equivalent does not exist,
and keep every 🔒 item optional and **off by default**, so a stock build is 100%
user-changeable.

---

## A. Branding ⚙️

| Setting | What it does | Mech | Default |
|---|---|---|---|
| Desktop wallpaper | Replace default `img0.jpg` + 4K resolution set. **Only visible when the background is set to Picture** — pair with `DesktopBackground = 0`, since Windows Spotlight overrides the wallpaper | ⚙️ | Org image; user can change |
| Lock screen image | Replace the default image **file** (not the policy, which locks it) | ⚙️ | Org image; changeable |
| Windows Spotlight off | Disable rotating lock screen / desktop Spotlight so branding shows | ✅ | Off |

## B. Default apps ⚙️

| Setting | What it does | Mech | Default |
|---|---|---|---|
| File / protocol associations | DISM `/Import-DefaultAppAssociations` with a modernized XML (drop 3D Viewer / Print 3D / Groove / Movies&TV) | ⚙️/✅ | Org defaults; changeable |

## C. Taskbar & Start (Windows 11)

| Setting | What it does | Mech | Default |
|---|---|---|---|
| Taskbar alignment | Left vs Center | ✅ | configurable |
| Search box mode | Hidden / icon / box | ✅ | Icon |
| Task View button | Show / hide | ✅ | configurable |
| Widgets button | Show / hide. Per-user `TaskbarDa` is blocked by the UCPD.sys driver, so this uses the `Dsh\AllowNewsAndInterests` machine policy | 🔒 | Off |
| New Outlook taskbar auto-pin | Suppress the auto-pinned new Outlook (keeps the app). Explorer pins it at first logon ignoring any seed, so a first-logon RunOnce sets `Taskband\AuxilliaryPins\MailPin=0`; pin shows on the **first** logon only, gone from the second on | ✅ | Off |
| Chat / Copilot / Teams button | Hide button + remove consumer Teams provisioned package | ✅ + ⚙️ | Off |
| Start "Recommended" / account & phone prompts | Trim Start clutter | ✅ | trimmed |
| Default Start pin layout | Seed `start2.bin` into the default profile (24H2-aware). The modern `ConfigureStartPins` applyOnce JSON is **MDM-only** (Intune Settings Catalog) — not an engine asset; ships as an optional add-on | ✅ | Org layout; changeable |
| Pinned **taskbar** apps | `LayoutModification.xml` at `%SystemDrive%\Users\Default\AppData\Local\Microsoft\Windows\Shell\` — sets default pins. **Requires `PinGeneration="N"` on every pin** (24H2/25H2) or the pins relock every logon (cache reapply); with it, user changes stick | ✅ | Org pins; changeable |
| Combine taskbar buttons / hide labels | `TaskbarGlomLevel` + secondary `MMTaskbarGlomLevel` seeded together (0 = always, 1 = when full, 2 = never) | ✅ | configurable |
| Seconds in system clock | `ShowSecondsInSystemClock` | ✅ | configurable |

## D. Explorer & desktop UX ✅

| Setting | What it does | Mech | Default |
|---|---|---|---|
| Launch Explorer to | This PC vs Home | ✅ | This PC |
| Show file extensions | Show known file extensions in Explorer | ✅ | On |
| Show hidden files | Show hidden files and folders | ✅ | configurable |
| Desktop icons | This PC / User Files / Network / Recycle Bin / Control Panel | ✅ | per-icon |
| Edge desktop shortcut | Delete public desktop `.lnk` | ⚙️ | Removed |
| App / system theme | Dark vs Light | ✅ | configurable |
| End task on right-click | Add "End Task" to the taskbar right-click menu | ✅ | configurable |
| Sync provider notifications | OneDrive promo notifications in File Explorer | ✅ | Off |
| Classic context menu | Default to the classic full right-click menu (no "Show more options") via the empty-default CLSID key. Applied by an **HKLM Active Setup** component (runs per-user before the shell at first logon; the key lives under `HKCU\Software\Classes`/UsrClass.dat, which isn't directly seedable) | ✅ | configurable |

## E. Debloat / privacy / first-run

| Setting | What it does | Mech | Default |
|---|---|---|---|
| Remove provisioned UWP apps | Curated removal list | ⚙️ | curated |
| Remove Office stub / new Outlook / Dev Home / Copilot app | Uninstall the consumer Office/OneNote stubs and listed apps | ⚙️ | configurable |
| Suggested content / consumer ads off | ContentDeliveryManager keys (changeable) instead of the `DisableWindowsConsumerFeatures` policy | ✅ | Off |
| Windows Tips off | SubscribedContent toggle | ✅ | Off |
| Bing / web results in Start search off | Disable Bing/web results in Start search | ✅ | Off |
| Advertising ID off | `AdvertisingInfo\Enabled` (non-policy; stays changeable) | ✅ | Off |
| Tailored experiences / "Personalized offers" off | `Privacy\TailoredExperiencesWithDiagnosticDataEnabled` (non-policy) | ✅ | Off |
| OneDrive auto-setup | Remove the default Run key | ✅ | Removed |
| Defender first-run prompt | Suppress | ✅ | Suppressed |
| Edge first-run experience | Policy — **locks** (no changeable equivalent) | 🔒 | Optional, off |
| OOBE privacy experience | One-time at OOBE; locking is moot | 🔒 | Optional, off |

## F. System behavior ⚙️

| Setting | What it does | Mech | Default |
|---|---|---|---|
| New network-location notification | Suppress | ⚙️ | Suppressed |
| Dynamic time zone | Location consent + `tzautoupdate` service | ⚙️ | On |
| Fast Startup | Enable / disable | ⚙️ | configurable |
| Clipboard history | `Software\Microsoft\Clipboard\EnableClipboardHistory` (non-policy; note the non-standard root) | ✅ | configurable |
| First logon animation | Policy (machine-wide) | 🔒 | Optional, off |

## G. Accessibility ✅

| Setting | What it does | Mech | Default |
|---|---|---|---|
| Sticky Keys shortcut | Disable the press-Shift-5-times prompt via the composite `Flags` string ("506" = off, "510" = on) | ✅ | configurable |

---

## Settings that inherently lock (🔒)

Four, all optional and off by default:

- Edge first-run experience
- OOBE privacy experience
- First logon animation
- Widgets button — the per-user `TaskbarDa` value is UCPD-blocked, so the `Dsh` machine policy is
  the only mechanism (greys out the toggle)

A stock build leaves all four unset, so the default solution is fully user-changeable.

## Dropped as obsolete (not carried forward)

Cortana (`AllowCortana`), Wi-Fi Sense, OOBE Cortana voice, legacy Edge
(`MicrosoftEdge\Main`) keys, 3D Viewer / Print 3D / Groove / Movies&TV associations,
Windows 10 News & Interests and People band, `Import-StartLayout`-based Start menu, the
Win+X cmd/PowerShell swap, and all Windows 10 code paths.
