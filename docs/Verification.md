# Verifying applied customizations

Many settings (privacy/debloat especially) have no obvious visual effect, so "did it work?"
is best answered by **reading the value back from the registry**, not by hunting through the UI.
This guide gives the fastest reliable check for each mechanism.

> All commands below are read-only. Run them from an **elevated** prompt.

---

## Fastest check: read the seeded Default User hive directly

`DefaultHive` settings are written into `C:\Users\Default\NTUSER.DAT`, which every **new** user
inherits. You can inspect that hive directly — no need to create a test user:

```powershell
reg load HKLM\WCVerify C:\Users\Default\NTUSER.DAT
# ...query values under HKLM\WCVerify\... (examples below)...
reg unload HKLM\WCVerify
```

> The hive must not be in use. Do this **before** signing in as the user you want to test, or
> from a separate admin session. If `reg load` fails with "being used by another process," sign
> out of any session that has loaded the default profile and retry.

To check a value, replace the `HKCU` root with `HKLM\WCVerify`. Example — taskbar alignment:

```powershell
reg query "HKLM\WCVerify\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarAl
```

To verify against an **already-created** test user instead, sign in as them and query the same
paths under `HKCU\...` directly.

---

## Hive-seeded settings (apply to new users)

Each row: the registry value the engine writes (under the loaded hive / a new user's `HKCU`) and
where the effect shows. These are seeded into the Default User hive — most are `DefaultHive`, a few
are `Custom` handlers that write into the same hive. `0`/`1` meanings are in the setting's catalog
`Description`.

| Setting | Value (under the hive root) | Where it shows in the UI |
|---|---|---|
| SearchBoxMode | `...\CurrentVersion\Search` \ `SearchboxTaskbarMode` (+ `SearchboxTaskbarModeCache` = 1). For **2 (search box) the hive holds neither value** by design: Windows writes 2 + cache 1 itself at first logon, so check a new user's HKCU instead | Taskbar search (Settings > Personalization > Taskbar > Search): 0 hide, 1 icon only, 2 search box, 3 icon and label |
| SmallerTaskbarButtons | `...\Explorer\Advanced` \ `IconSizePreference` | Taskbar > Taskbar behaviors > Show smaller taskbar buttons (0 always, 1 never, 2 when full) |
| TaskbarAlignment | `...\Explorer\Advanced` \ `TaskbarAl` | Taskbar left/center |
| TaskbarPosition | `...\Explorer\Advanced` \ `TaskbarLocation` (+ `...\CurrentVersion\RunOnce` \ `WC_TaskbarLocation` for 0/1/2: a `cmd /c reg add … /d 3 & ping … & reg add … /d <value>` line, consumed at the user's first logon - absent afterwards) | Taskbar > Taskbar behaviors > Taskbar position (0 left, 1 top, 2 right, 3 bottom); 26H2 26300.9711+. The taskbar itself moves a few seconds into the first logon, when the RunOnce fires; explorer ignores a write of the value it already holds, hence the bottom-first double write |
| TaskbarSize | `...\Explorer\Advanced` \ `TaskbarSize` | Taskbar > Taskbar behaviors > Taskbar size (0 default, 1 small); 26H2 26300.9711+ |
| WidgetsButton | `HKLM\...\Policies\Microsoft\Dsh` \ `AllowNewsAndInterests` (machine policy; locks) | Widgets button on the taskbar |
| TaskViewButton | `...\Explorer\Advanced` \ `ShowTaskViewButton` | Task View button |
| TaskbarEndTask | `...\Explorer\Advanced\TaskbarDeveloperSettings` \ `TaskbarEndTask` | "End Task" in taskbar right-click |
| InkWorkspaceIcon | `...\PenWorkspace` \ `PenWorkspaceButtonDesiredVisibility` | Pen menu icon |
| TouchKeyboardIcon | `...\TabletTip\1.7` \ `TipbandDesiredVisibility` | Touch keyboard icon |
| StartTrackRecentDocs | `...\Explorer\Advanced` \ `Start_TrackDocs` | Start > Settings > Personalization > Start > "Show recommended files…" |
| StartTrackMostUsed | `...\Explorer\Advanced` \ `Start_TrackProgs` | Start settings > "Show most used apps" |
| LaunchTo | `...\Explorer\Advanced` \ `LaunchTo` | File Explorer opens to This PC vs Home |
| HideFileExt | `...\Explorer\Advanced` \ `HideFileExt` | File Explorer > known file extensions |
| HiddenFiles | `...\Explorer\Advanced` \ `Hidden` | File Explorer > hidden items |
| ColorMode | `...\Themes` \ `CurrentTheme` + `...\Themes\Personalize` \ `AppsUseLightTheme`/`SystemUsesLightTheme` | App & system color mode (dark/light). CurrentTheme is the durable switch; the DWORDs alone are re-asserted from the .theme at first logon. |
| DesktopBackground | `...\Explorer\Wallpapers` \ `BackgroundType` (+ `...\DesktopSpotlight\Settings` \ `EnabledState`) | Background source: 0 = Picture, 3 = Windows Spotlight (non-locking) |
| *DesktopIcon | `...\Explorer\HideDesktopIcons\NewStartPanel` \ `{GUID}` | Desktop icons: This PC, User Files, Network, Control Panel (Recycle Bin sets the GUID under both `NewStartPanel` and `ClassicStartMenu`) |
| BingSearchEnabled | `...\CurrentVersion\Search` \ `BingSearchEnabled` | Start search shows web/Bing results when `1` |
| WindowsTips | `...\ContentDeliveryManager` \ `SubscribedContent-338389Enabled` | Windows tip notifications |
| SuggestedContentSettings | `...\ContentDeliveryManager` \ `SubscribedContent-338393Enabled`, `-353694Enabled`, `-353696Enabled` (all three) | Privacy & security > Recommendations & offers > "Recommendations and offers in Settings" (shows On if any of the three is missing) |
| SuggestedContentStart | `...\ContentDeliveryManager` \ `SubscribedContent-338388Enabled` | Promoted apps in Start |
| StartSuggestions | `...\ContentDeliveryManager` \ `SystemPaneSuggestionsEnabled` | Tips/suggestions in the Start pane |
| SilentInstalledApps | `...\ContentDeliveryManager` \ `SilentInstalledAppsEnabled` | Auto-installed promoted apps |
| PreInstalledApps | `...\ContentDeliveryManager` \ `PreInstalledAppsEnabled` | Pre-installed suggested apps |
| OemPreInstalledApps | `...\ContentDeliveryManager` \ `OemPreInstalledAppsEnabled` | OEM suggested apps |
| SpotlightLockScreen | `...\ContentDeliveryManager` \ `RotatingLockScreenEnabled` | Spotlight rotating lock screen |
| SpotlightLockScreenOverlay | `...\ContentDeliveryManager` \ `RotatingLockScreenOverlayEnabled` | Spotlight lock-screen tips overlay |
| DefenderPrompt | `SOFTWARE\Microsoft\Windows Defender` \ `UifirstRun` | Defender first-run prompt (`0` = suppressed) |
| ShowSecondsInClock | `...\Explorer\Advanced` \ `ShowSecondsInSystemClock` | Seconds in the system tray clock |
| SyncProviderNotifications | `...\Explorer\Advanced` \ `ShowSyncProviderNotifications` | OneDrive sync-provider notifications in File Explorer |
| CombineTaskbarButtons | `...\Explorer\Advanced` \ `TaskbarGlomLevel` (+ `MMTaskbarGlomLevel`) | Combine taskbar buttons / hide labels |
| AdvertisingId | `...\CurrentVersion\AdvertisingInfo` \ `Enabled` | Privacy & security > General > advertising ID |
| TailoredExperiences | `...\CurrentVersion\Privacy` \ `TailoredExperiencesWithDiagnosticDataEnabled` | Privacy & security > General > "Personalized offers" |
| ClipboardHistory | `Software\Microsoft\Clipboard` \ `EnableClipboardHistory` | System > Clipboard > Clipboard history |
| CloudSearchMicrosoftAccount / CloudSearchWorkAccount | `...\CurrentVersion\SearchSettings` \ `IsMSACloudSearchEnabled` / `IsAADCloudSearchEnabled` | Privacy & security > Search > Cloud content search > Microsoft account / Work or School account |
| FeedbackFrequency | `Software\Microsoft\Siuf\Rules` \ `NumberOfSIUFInPeriod` | Privacy & security > Diagnostics & feedback > Feedback frequency = Never |
| GameBarControllerButton | `Software\Microsoft\GameBar` \ `UseNexusForGameBarEnabled` | Gaming > Game Bar > Allow your controller to open Game Bar |
| StickyKeysShortcut | `Control Panel\Accessibility\StickyKeys` \ `Flags` (REG_SZ; `506` = off, `510` = on) | Accessibility > Keyboard > Sticky keys shortcut |

The privacy/debloat values (`ContentDeliveryManager`, `BingSearchEnabled`, `DefenderPrompt`)
rarely have a *visible* effect — confirm them by reading the value, not by looking at the UI.

---

## Machine-level (HKLM) settings

Read these from the live machine (no hive load needed):

```powershell
# FastStartup
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v HiberbootEnabled
# EdgeFirstRun (Policy)
reg query "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v HideFirstRunExperience
# OOBEPrivacyExperience (Policy) — only takes effect during OOBE of a fresh setup
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\OOBE" /v DisablePrivacyExperience
# FirstLogonAnimation (Policy)
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableFirstLogonAnimation
```

---

## Mechanism-specific checks

| Setting | How to verify |
|---|---|
| RemoveProvisionedApps | `Get-AppxProvisionedPackage -Online \| Select DisplayName` — removed names should be absent |
| RemoveOfficeApps | Requires a device that shipped the consumer Office/OneNote stubs; check `Get-AppxProvisionedPackage` for `Microsoft.MicrosoftOfficeHub` etc. |
| DefaultAppAssociations | `Dism /Online /Get-DefaultAppAssociations` shows the imported set (applies to new users at first logon) |
| TaskbarPins / StartLayout | Confirm the file landed: `Get-Item C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\LayoutModification.xml` (and `...\Packages\...StartMenuExperienceHost...\LocalState\start2.bin`); then sign in as a new user |
| EdgeDesktopShortcut | Check both the **public** desktop (`C:\Users\Public\Desktop`) and a **new user's** desktop |
| OneDriveSetup | `reg query "HKLM\WCVerify\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v OneDriveSetup` should be absent in the default hive |
| ClassicContextMenu | Machine: the Active Setup component `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{B1E9F2A4-7C3D-4E5F-9A1B-0C7E5D3F2A18}` exists with a `StubPath`. Per-user (after first logon): `HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32` has an empty `(Default)`, and the right-click menu is the classic full menu |
| NetworkNotification / DynamicTime | Behavioral (no per-user value to read back) |
