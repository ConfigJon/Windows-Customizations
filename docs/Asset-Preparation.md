# Asset Preparation Guide

The customization engine ships the *logic*; the **content** it applies — branding images,
default app associations, the Start menu layout, and taskbar pins — is specific to your
organization and must be **captured from a reference machine**. This guide walks through
producing each asset and placing it in the repository.

---

## Before you start: the reference machine

Capture assets from a **clean Windows 11 device** that matches your deployment target:

- Same **edition** (e.g. Enterprise) and ideally the same **feature update** (e.g. 24H2/25H2)
  as the machines you'll deploy to. Start-menu and taskbar layout files are build-sensitive.
- A throwaway/VM is ideal — you'll be installing apps and rearranging the Start menu/taskbar to
  the exact state you want end users to inherit.
- Do the capture under a **normal local user profile** (not the default profile), then export.

You will produce up to four asset sets:

| Asset | Output file(s) | Repo destination |
|---|---|---|
| Default app associations | `AppAssociations.xml` | `package\Assets\AppAssociations\` |
| Start menu layout | `start2.bin` | `package\Assets\Layout\` |
| Taskbar pins | `LayoutModification.xml` | `package\Assets\Layout\` |
| Branding | wallpapers, lock screen | `package\Assets\Branding\` |

Only capture the assets whose customizations you've enabled in `package\Config\Settings.json`.

---

## 1. Default app associations (`AppAssociations.xml`)

Defines which app opens each file type / protocol (browser, PDF, media, mail, etc.). Applied
with DISM as a **default** — users can still change associations afterward.

1. On the reference machine, **install** the apps you want as defaults (e.g. VLC, Acrobat
   Reader) and set each as the default for its file types via
   **Settings → Apps → Default apps**.
2. Export the current association set from an **elevated** prompt:
   ```
   Dism /Online /Export-DefaultAppAssociations:"C:\Temp\AppAssociations.xml"
   ```
3. Open the XML and **trim** entries you don't care about. Remove associations for apps that no
   longer ship with Windows 11 (e.g. 3D Viewer, Print 3D, Groove Music, Movies & TV) — leaving
   stale ProgIDs can cause "an app default was reset" notifications.
4. Save it to `package\Assets\AppAssociations\AppAssociations.xml`.

> **Tip:** keep the file minimal — only the associations you actually want to enforce as
> defaults. Everything you remove falls back to the Windows default (trimmed entries are *not*
> blanked out). Trimming the export is safe and is in fact the fix for the old "An app default
> was reset" toasts, which are caused by leaving **stale ProgIDs** in the file (associations
> pointing at apps that aren't installed), not by removing entries.
>
> **Imports are not cumulative.** `Import-DefaultAppAssociations` does not merge files — the last
> import wins. Keep every association you care about in a single consolidated file. The defaults
> apply at **first logon of new users only**; existing profiles are untouched.

---

## 2. Start menu layout

Controls the pinned-apps layout of the Start menu. There are **two ways** to deliver it, and they
are not interchangeable — pick based on how the device is managed:

| Method | Delivered by | Works on | In this package? |
|---|---|---|---|
| **A. `start2.bin` seed** | Copied into the default user profile (this package) | Any device, no enrollment needed | ✅ yes (`StartLayout` catalog entry) |
| **B. `ConfigureStartPins` JSON** | Intune **Settings Catalog** policy | **Intune/MDM-enrolled devices only** | ❌ no — assign separately in Intune |

Devices deployed with Configuration Manager that are not co-managed with Intune can only use
method A.

> **Why not apply the JSON from the engine?** `ConfigureStartPins` is consumed **only through the
> MDM/PolicyManager channel.** A SYSTEM/Win32 registry write to
> `HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer` (`ConfigureStartPins` + `ConfigureStartPinsJSON`)
> is **not** bridged into `HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Start` unless the
> device is MDM-enrolled, so the Start host never reads it. Writing those values (as content *and* as
> a file path) leaves the Start menu unchanged for new users on a non-enrolled device. This is why the
> engine can't own method B — it must be an Intune assignment.

### Method A — `start2.bin` seed (self-contained, this package)

New users inherit the layout but can re-pin freely.

1. On the reference machine, arrange the **Start menu pins** exactly as you want them (pin/unpin
   apps, order them).
2. Sign out and back in (or reboot) so the layout is written to disk.
3. Copy the layout file from your profile:
   ```
   %LocalAppData%\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState\start2.bin
   ```
4. Save it to `package\Assets\Layout\start2.bin`.

> **Build caveat:** the filename changed across Windows 11 releases (`start.bin` → `start2.bin`).
> On current builds it is **`start2.bin`** — confirm the exact filename on *your* reference build
> and update `package\Engine\Catalog.psd1` / `package\Config\Settings.json` if it differs. The package folder name
> (`Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy`) should also be verified on your build.

### Method B — `ConfigureStartPins` JSON via Intune (recommended for Autopilot/Intune fleets)

Build-robust (no binary blob, no build-sensitive package path), human-readable, officially
documented, and `applyOnce` gives the same user-changeable-default behavior. Because every
Autopilot device is Intune-enrolled, this is the cleaner long-term path for the pinned list.

1. Arrange the Start pins on the reference machine, then export:
   ```powershell
   Export-StartLayout -Path "C:\Layouts\StartPins.json"
   ```
2. **Add `applyOnce` yourself** — `Export-StartLayout` does **not** emit it. Without
   `"applyOnce": true` the list is re-applied at every logon (a *lock*, which defeats the
   user-changeable goal). Edit the JSON so it reads:
   ```json
   {
       "applyOnce": true,
       "pinnedList": [
           { "desktopAppLink": "%ALLUSERSPROFILE%\\Microsoft\\Windows\\Start Menu\\Programs\\Microsoft Edge.lnk" },
           { "packagedAppId": "Microsoft.WindowsStore_8wekyb3d8bbwe!App" }
       ]
   }
   ```
   - `packagedAppId` = UWP app AUMID; `desktopAppLink` = path to a `.lnk`; `desktopAppId` = a Win32
     AUMID; `secondaryTile` = an Edge pinned site.
   - Any `.lnk` you reference (e.g. Chrome, VLC) **must exist on the target before first logon** or
     that pin is silently dropped. Prefer `%ALLUSERSPROFILE%` (All Users Start Menu) shortcuts.
3. Save it to `package\Assets\Layout\StartPins.json` (kept as a reference artifact; it is *not* applied by
   the engine).
4. In **Intune → Settings Catalog**, create a policy with **Start → "Configure Start Pins"** (or
   **"Configure Start Pins (User)"**) and paste the JSON content as the value. Assign it to the
   same devices/users as this package. Requires Windows 11 **24H2 + KB5062660** or **25H2**.

> Use **either** A or B for a given fleet, not both — two layouts competing for the same pins is
> undefined. If you adopt B, disable the `StartLayout` entry in `package\Config\Settings.json`.

---

## 3. Taskbar pins (`LayoutModification.xml`)

Sets the **default** taskbar pinned apps. The engine seeds this file into the default profile so
new users inherit the pins.

> **Critical for 24H2/25H2 — use `PinGeneration` or it becomes a lock.** On current builds the
> taskbar layout is **reapplied every time `explorer.exe` restarts (i.e. every logon)** from a
> cached copy of the layout (`HKCU\…\CloudStore`), overwriting the user's pin changes — *by
> design*. Deleting the per-user file does **not** stop this (the old 22H2/23H2 "RunOnce delete"
> trick is dead). The supported fix is the **`PinGeneration="N"`** attribute (Win11 24H2 +
> KB5060829 / 25H2 — the taskbar's equivalent of Start's `applyOnce`):
> - **No `PinGeneration`** → user unpins, it's repinned next logon = *lock*.
> - **`PinGeneration="1"`** → seeded once; if the user unpins, it **stays unpinned**. ✅ the
>   changeable default this project wants. (Bump the number later to force a re-push.)
>
> Put `PinGeneration` on **every** pin. With the default-profile seed, pins appear for a new user and
> removed pins do not return after sign-out/in. Caveat: on a build *older* than 24H2+KB5060829 the
> attribute makes **no** pins apply — fine for a 25H2 target.

1. Author the XML. Example (replaces the default pins; every pin carries `PinGeneration="1"`):
   ```xml
   <?xml version="1.0" encoding="utf-8"?>
   <LayoutModificationTemplate
       xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification"
       xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout"
       xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout"
       xmlns:taskbar="http://schemas.microsoft.com/Start/2014/TaskbarLayout"
       Version="1">
     <CustomTaskbarLayoutCollection PinListPlacement="Replace">
       <defaultlayout:TaskbarLayout>
         <taskbar:TaskbarPinList>
           <taskbar:DesktopApp DesktopApplicationID="Microsoft.Windows.Explorer" PinGeneration="1"/>
           <taskbar:DesktopApp DesktopApplicationID="MSEdge" PinGeneration="1"/>
           <taskbar:UWA AppUserModelID="Microsoft.Windows.Photos_8wekyb3d8bbwe!App" PinGeneration="1"/>
           <taskbar:DesktopApp DesktopApplicationLinkPath="%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\App.lnk" PinGeneration="1"/>
         </taskbar:TaskbarPinList>
       </defaultlayout:TaskbarLayout>
     </CustomTaskbarLayoutCollection>
   </LayoutModificationTemplate>
   ```
   - **`taskbar:UWA AppUserModelID=…`** for UWP/Store apps (the *only* form that pins UWP apps).
   - **`taskbar:DesktopApp`** for desktop apps — either `DesktopApplicationID` (an AUMID, e.g.
     `Microsoft.Windows.Explorer`, `MSEdge`, `Chrome`) **or** `DesktopApplicationLinkPath` (path to a
     `.lnk`). The easiest way to get a working `DesktopApplicationID` is `Get-StartApps`, which lists
     each installed app's display name and `AppID`.
   - A `DesktopApplicationLinkPath` `.lnk` must exist on the target before first logon, or that pin
     is silently dropped. Prefer `%ALLUSERSPROFILE%` (All Users) shortcuts.
   - `PinListPlacement="Replace"` replaces the default pins entirely; omit it to append.
2. Save it to `package\Assets\Layout\LayoutModification.xml`.

> The engine copies this to
> `C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\LayoutModification.xml`. With
> `PinGeneration` on each pin this sets the default pins **without locking them**.

---

## 4. Branding (wallpaper, lock screen)

Replaces the default desktop wallpaper and lock screen image. Both are applied as file
replacements so users can still change them.

### 4a. Desktop wallpaper

Windows ships a base `img0.jpg` plus a 4K render. **Older builds shipped a full multi-resolution
set** (`1024x768` … `3840x2160` plus portrait variants), but current builds (e.g. a fresh **25H2** or
**26H2** install) ship only a single 1920x1200 render in the 4K folder. They also ship a second,
**dark** wallpaper, `img19`, which `dark.theme` uses:

```
C:\Windows\Web\Wallpaper\Windows\img0.jpg                 <- light (Windows (light) / aero.theme)
C:\Windows\Web\Wallpaper\Windows\img19.jpg                <- dark (Windows (dark) / dark.theme)
C:\Windows\Web\4K\Wallpaper\Windows\img0_1920x1200.jpg    <- only 4K variants present
C:\Windows\Web\4K\Wallpaper\Windows\img19_1920x1200.jpg
```

> **Dark mode needs the dark slot branded.** `ColorMode = 0` seeds `dark.theme`, so new users see
> `img19`, not `img0`. The engine brands both: supply only `img0.jpg` (+ `4k\img0_*.jpg`) and it is
> reused for the dark slot, or supply a separate `img19.jpg` (+ `4k\img19_*.jpg`) to give dark mode its
> own render.

Only files that already exist as Windows defaults are referenced — dropping extra resolutions
(e.g. `img0_3840x2160.jpg`) just leaves unused files on disk. **Check the 4K folder on *your*
reference build** and render to whatever variants it actually contains.

1. Produce your wallpaper as `.jpg`. On 25H2/26H2 you need just two renders: the base image and a
   1920x1200 version.
2. Place the base image as `package\Assets\Branding\img0.jpg` and the 4K render(s) under
   `package\Assets\Branding\4k\` (filenames matching the originals on your build, e.g. `img0_1920x1200.jpg`).
3. *(Optional)* For a different dark-mode image, add `package\Assets\Branding\img19.jpg` and
   `package\Assets\Branding\4k\img19_1920x1200.jpg`. When you supply `img19.jpg`, the engine stops
   reusing the `img0` 4K renders for the dark slot, so include the dark 4K render too.

### 4b. Lock screen image

1. Provide a single high-resolution `.jpg` (target your most common display, e.g. 3840x2160).
2. Save it as `package\Assets\Branding\img100.jpg`. The engine takes ownership of and replaces
   `%WinDir%\Web\Screen\img100.jpg` (the default lock-screen image file) rather than setting the
   locking personalization policy, so users can still change their lock screen.

---

## Checklist

- [ ] Reference machine matches target edition/build
- [ ] `AppAssociations.xml` exported and trimmed → `package\Assets\AppAssociations\`
- [ ] Start layout: **either** `start2.bin` captured (Method A, filename verified) → `package\Assets\Layout\`
      **or** `StartPins.json` (`applyOnce: true`) assigned via Intune Settings Catalog (Method B) — not both
- [ ] `LayoutModification.xml` authored, **`PinGeneration` on every pin** (24H2/25H2) → `package\Assets\Layout\`
- [ ] Wallpapers (base + 1920x1200; verify your build's 4K set), lock screen → `package\Assets\Branding\`
- [ ] Only assets for **enabled** customizations are included
- [ ] Build the package with `tools\New-Package.ps1` after assets are in place

---

## Verifying your assets

Before packaging for production, test on a spare device or VM:

1. Apply the assets to a test default profile (or run the engine locally as SYSTEM via PsExec).
2. Create a **new** local user and sign in — confirm the wallpaper, lock screen, Start layout,
   taskbar pins, and default apps match your intent. **Note:** Method B (`ConfigureStartPins` JSON)
   will *not* take effect on a non-MDM-enrolled test box — verify it on an Intune-enrolled device.
3. Confirm a standard (non-admin) user can still **change** each setting — that's the whole point.
