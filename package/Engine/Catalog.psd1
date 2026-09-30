@{
    # =====================================================================================
    # Windows Customizations catalog (Windows 11)
    #
    # Each entry fully describes one customization. The per-deployment Config\Settings.json
    # selects values by Name. See docs\Design.md (section 3) for the field reference and
    # docs\Customizations.md for the full target list.
    #
    # Mechanism:  DefaultHive | HKLM | Policy | File | AppRemoval | Dism | Custom
    #   DefaultHive = user-changeable default (seeded into C:\Users\Default\NTUSER.DAT)
    #   HKLM        = machine value (non-policy)
    #   Policy      = GP-backed value -> LOCKS the setting (off by default; use deliberately)
    #
    # NOTE: a few keys are build-sensitive or less commonly documented (flagged "verify").
    # Confirm them on a reference Windows 11 image before production use.
    # =====================================================================================
    Customizations = @(

        # =========================== TASKBAR (DefaultHive) ==================================
        @{
            Name          = 'SearchBoxMode'
            Category      = 'Taskbar'
            Description   = 'Taskbar search: 0 = hidden, 1 = icon only, 2 = search box, 3 = icon and label'
            Mechanism     = 'Custom'
            NeedsHive     = $true
            AllowedValues = @(0, 1, 2, 3)
        },
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
            Name          = 'TaskViewButton'
            Category      = 'Taskbar'
            Description   = 'Task View button: 0 = hidden, 1 = shown'
            Mechanism     = 'DefaultHive'
            Path          = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
            ValueName     = 'ShowTaskViewButton'
            Type          = 'DWord'
            AllowedValues = @(0, 1)
        },
        @{
            Name          = 'TaskbarEndTask'
            Category      = 'Taskbar'
            Description   = 'End Task on taskbar right-click: 0 = off, 1 = on'
            Mechanism     = 'DefaultHive'
            Path          = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDeveloperSettings'
            ValueName     = 'TaskbarEndTask'
            Type          = 'DWord'
            AllowedValues = @(0, 1)
        },
        @{
            Name          = 'InkWorkspaceIcon'
            Category      = 'Taskbar'
            Description   = 'Pen/Ink Workspace icon: 0 = hidden, 1 = shown'
            Mechanism     = 'DefaultHive'
            Path          = 'SOFTWARE\Microsoft\Windows\CurrentVersion\PenWorkspace'
            ValueName     = 'PenWorkspaceButtonDesiredVisibility'
            Type          = 'DWord'
            AllowedValues = @(0, 1)
        },
        @{
            Name          = 'TouchKeyboardIcon'
            Category      = 'Taskbar'
            Description   = 'Touch keyboard icon: 0 = hidden, 1 = shown'
            Mechanism     = 'DefaultHive'
            Path          = 'SOFTWARE\Microsoft\TabletTip\1.7'
            ValueName     = 'TipbandDesiredVisibility'
            Type          = 'DWord'
            AllowedValues = @(0, 1)
        },

        @{
            Name          = 'ResumeButton'
            Category      = 'Taskbar'
            Description   = 'Cross-device Resume taskbar badge: 0 = off, 1 = on'
            Mechanism     = 'DefaultHive'
            Path          = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
            ValueName     = 'IsEnabled'
            Type          = 'DWord'
            AllowedValues = @(0, 1)
        },
        @{
            Name          = 'OutlookTaskbarPin'
            Category      = 'Taskbar'
            Description   = 'Auto-pin the new Outlook app to the taskbar for new users: 0 = no, 1 = yes'
            Mechanism     = 'Custom'
            NeedsHive     = $true
            AllowedValues = @(0, 1)
        },

        @{
            Name          = 'CombineTaskbarButtons'
            Category      = 'Taskbar'
            Description   = 'Combine taskbar buttons and hide labels: 0 = always, 1 = when taskbar is full, 2 = never'
            Mechanism     = 'Custom'
            NeedsHive     = $true
            AllowedValues = @(0, 1, 2)
        },
        @{
            Name          = 'ShowSecondsInClock'
            Category      = 'Taskbar'
            Description   = 'Show seconds in the system tray clock (uses more power): 0 = off, 1 = on'
            Mechanism     = 'DefaultHive'
            Path          = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
            ValueName     = 'ShowSecondsInSystemClock'
            Type          = 'DWord'
            AllowedValues = @(0, 1)
        },
        @{
            Name          = 'SmallerTaskbarButtons'
            Category      = 'Taskbar'
            Description   = 'Show smaller taskbar buttons: 0 = always, 1 = never, 2 = when taskbar is full'
            Mechanism     = 'DefaultHive'
            Path          = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
            ValueName     = 'IconSizePreference'
            Type          = 'DWord'
            AllowedValues = @(0, 1, 2)
        },

        # =========================== START (DefaultHive) ====================================
        @{
            Name          = 'StartTrackRecentDocs'
            Category      = 'Start'
            Description   = 'Show recently opened items in Start/Jump Lists: 0 = off, 1 = on'
            Mechanism     = 'DefaultHive'
            Path          = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
            ValueName     = 'Start_TrackDocs'
            Type          = 'DWord'
            AllowedValues = @(0, 1)
        },
        @{
            Name          = 'StartTrackMostUsed'
            Category      = 'Start'
            Description   = 'Show most-used apps in Start: 0 = off, 1 = on'
            Mechanism     = 'DefaultHive'
            Path          = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
            ValueName     = 'Start_TrackProgs'
            Type          = 'DWord'
            AllowedValues = @(0, 1)
        },

        @{
            Name          = 'StartAccountNotifications'
            Category      = 'Start'
            Description   = 'Account-related notifications on Start: 0 = off, 1 = on'
            Mechanism     = 'DefaultHive'
            Path          = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
            ValueName     = 'Start_AccountNotifications'
            Type          = 'DWord'
            AllowedValues = @(0, 1)
        },
        @{
            Name          = 'StartRecentlyAddedApps'
            Category      = 'Start'
            Description   = 'Show recently added apps in Start: 0 = off, 1 = on'
            Mechanism     = 'DefaultHive'
            Path          = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Start'
            ValueName     = 'ShowRecentList'
            Type          = 'DWord'
            AllowedValues = @(0, 1)
        },
        @{
            Name          = 'StartRecommendations'
            Category      = 'Start'
            Description   = 'Show recommendations for tips, shortcuts and new apps in Start: 0 = off, 1 = on'
            Mechanism     = 'DefaultHive'
            Path          = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
            ValueName     = 'Start_IrisRecommendations'
            Type          = 'DWord'
            AllowedValues = @(0, 1)
        },
        @{
            Name          = 'StartAllAppsView'
            Category      = 'Start'
            Description   = 'Start menu "All apps" view: 0 = Category, 1 = Grid, 2 = List'
            Mechanism     = 'DefaultHive'
            Path          = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Start'
            ValueName     = 'AllAppsViewMode'
            Type          = 'DWord'
            AllowedValues = @(0, 1, 2)
        },

        # =========================== EXPLORER & DESKTOP (DefaultHive) =======================
        @{
            Name          = 'LaunchTo'
            Category      = 'Explorer'
            Description   = 'File Explorer opens to: 1 = This PC, 2 = Quick access/Home'
            Mechanism     = 'DefaultHive'
            Path          = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
            ValueName     = 'LaunchTo'
            Type          = 'DWord'
            AllowedValues = @(1, 2)
        },
        @{
            Name          = 'HideFileExt'
            Category      = 'Explorer'
            Description   = 'Known file extensions: 0 = show, 1 = hide'
            Mechanism     = 'DefaultHive'
            Path          = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
            ValueName     = 'HideFileExt'
            Type          = 'DWord'
            AllowedValues = @(0, 1)
        },
        @{
            Name          = 'HiddenFiles'
            Category      = 'Explorer'
            Description   = 'Hidden files and folders: 1 = show, 2 = hide'
            Mechanism     = 'DefaultHive'
            Path          = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
            ValueName     = 'Hidden'
            Type          = 'DWord'
            AllowedValues = @(1, 2)
        },
        @{
            Name          = 'ColorMode'
            Category      = 'Explorer'
            Description   = 'Default app & system color mode: 0 = dark, 1 = light'
            Mechanism     = 'Custom'
            NeedsHive     = $true
            AllowedValues = @(0, 1)
        },
        @{
            Name          = 'ThisPCDesktopIcon'
            Category      = 'Explorer'
            Description   = 'This PC desktop icon: 0 = shown, 1 = hidden'
            Mechanism     = 'DefaultHive'
            Path          = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel'
            ValueName     = '{20D04FE0-3AEA-1069-A2D8-08002B30309D}'
            Type          = 'DWord'
            AllowedValues = @(0, 1)
        },
        @{
            Name          = 'UserFilesDesktopIcon'
            Category      = 'Explorer'
            Description   = 'User Files desktop icon: 0 = shown, 1 = hidden'
            Mechanism     = 'DefaultHive'
            Path          = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel'
            ValueName     = '{59031a47-3f72-44a7-89c5-5595fe6b30ee}'
            Type          = 'DWord'
            AllowedValues = @(0, 1)
        },
        @{
            Name          = 'NetworkDesktopIcon'
            Category      = 'Explorer'
            Description   = 'Network desktop icon: 0 = shown, 1 = hidden'
            Mechanism     = 'DefaultHive'
            Path          = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel'
            ValueName     = '{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}'
            Type          = 'DWord'
            AllowedValues = @(0, 1)
        },
        @{
            Name          = 'ControlPanelDesktopIcon'
            Category      = 'Explorer'
            Description   = 'Control Panel desktop icon: 0 = shown, 1 = hidden'
            Mechanism     = 'DefaultHive'
            Path          = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel'
            ValueName     = '{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}'
            Type          = 'DWord'
            AllowedValues = @(0, 1)
        },
        @{
            Name          = 'RecycleBinDesktopIcon'
            Category      = 'Explorer'
            Description   = 'Recycle Bin desktop icon (sets both icon panels): 0 = shown, 1 = hidden'
            Mechanism     = 'Custom'
            NeedsHive     = $true
            AllowedValues = @(0, 1)
        },
        @{
            Name        = 'EdgeDesktopShortcut'
            Category    = 'Explorer'
            Description = 'Delete the public-desktop Microsoft Edge shortcut'
            Mechanism   = 'Custom'
            NeedsHive   = $false
        },

        @{
            Name          = 'SyncProviderNotifications'
            Category      = 'Explorer'
            Description   = 'Sync provider (OneDrive promo) notifications in File Explorer: 0 = off, 1 = on'
            Mechanism     = 'DefaultHive'
            Path          = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
            ValueName     = 'ShowSyncProviderNotifications'
            Type          = 'DWord'
            AllowedValues = @(0, 1)
        },
        @{
            Name          = 'ClassicContextMenu'
            Category      = 'Explorer'
            Description   = 'Right-click context menu: 0 = Windows 11 (Show more options), 1 = classic full menu'
            Mechanism     = 'Custom'
            NeedsHive     = $false
            AllowedValues = @(0, 1)
        },

        # =========================== DEBLOAT / PRIVACY / SEARCH =============================
        @{
            Name          = 'BingSearchEnabled'
            Category      = 'Debloat'
            Description   = 'Bing/web results in Start search: 0 = off, 1 = on'
            Mechanism     = 'DefaultHive'
            Path          = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Search'
            ValueName     = 'BingSearchEnabled'
            Type          = 'DWord'
            AllowedValues = @(0, 1)
        },
        @{
            Name          = 'CloudSearchMicrosoftAccount'
            Category      = 'Debloat'
            Description   = 'Windows Search results from the personal Microsoft account (e.g. OneDrive, Outlook): 0 = off, 1 = on'
            Mechanism     = 'DefaultHive'
            Path          = 'SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings'
            ValueName     = 'IsMSACloudSearchEnabled'
            Type          = 'DWord'
            AllowedValues = @(0, 1)
        },
        @{
            Name          = 'CloudSearchWorkAccount'
            Category      = 'Debloat'
            Description   = 'Windows Search results from the work or school account (e.g. OneDrive, SharePoint, Outlook): 0 = off, 1 = on'
            Mechanism     = 'DefaultHive'
            Path          = 'SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings'
            ValueName     = 'IsAADCloudSearchEnabled'
            Type          = 'DWord'
            AllowedValues = @(0, 1)
        },
        @{
            Name          = 'WindowsTips'
            Category      = 'Debloat'
            Description   = 'Windows tips/suggestions: 0 = off, 1 = on'
            Mechanism     = 'DefaultHive'
            Path          = 'SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
            ValueName     = 'SubscribedContent-338389Enabled'
            Type          = 'DWord'
            AllowedValues = @(0, 1)
        },
        @{
            Name          = 'SuggestedContentSettings'
            Category      = 'Debloat'
            Description   = 'Recommendations and offers (suggested content) in the Settings app: 0 = off, 1 = on'
            Mechanism     = 'Custom'
            NeedsHive     = $true
            AllowedValues = @(0, 1)
        },
        @{
            Name          = 'SuggestedContentStart'
            Category      = 'Debloat'
            Description   = 'App suggestions/promoted apps in Start: 0 = off, 1 = on'
            Mechanism     = 'DefaultHive'
            Path          = 'SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
            ValueName     = 'SubscribedContent-338388Enabled'
            Type          = 'DWord'
            AllowedValues = @(0, 1)
        },
        @{
            Name          = 'StartSuggestions'
            Category      = 'Debloat'
            Description   = 'Tips/suggestions on the Start menu pane: 0 = off, 1 = on'
            Mechanism     = 'DefaultHive'
            Path          = 'SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
            ValueName     = 'SystemPaneSuggestionsEnabled'
            Type          = 'DWord'
            AllowedValues = @(0, 1)
        },
        @{
            Name          = 'SilentInstalledApps'
            Category      = 'Debloat'
            Description   = 'Silent auto-install of suggested apps: 0 = off, 1 = on'
            Mechanism     = 'DefaultHive'
            Path          = 'SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
            ValueName     = 'SilentInstalledAppsEnabled'
            Type          = 'DWord'
            AllowedValues = @(0, 1)
        },
        @{
            Name          = 'PreInstalledApps'
            Category      = 'Debloat'
            Description   = 'Pre-installed suggested apps: 0 = off, 1 = on'
            Mechanism     = 'DefaultHive'
            Path          = 'SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
            ValueName     = 'PreInstalledAppsEnabled'
            Type          = 'DWord'
            AllowedValues = @(0, 1)
        },
        @{
            Name          = 'OemPreInstalledApps'
            Category      = 'Debloat'
            Description   = 'OEM pre-installed suggested apps: 0 = off, 1 = on'
            Mechanism     = 'DefaultHive'
            Path          = 'SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
            ValueName     = 'OemPreInstalledAppsEnabled'
            Type          = 'DWord'
            AllowedValues = @(0, 1)
        },
        @{
            Name          = 'SpotlightLockScreen'
            Category      = 'Debloat'
            Description   = 'Windows Spotlight rotating lock screen: 0 = off, 1 = on'
            Mechanism     = 'DefaultHive'
            Path          = 'SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
            ValueName     = 'RotatingLockScreenEnabled'
            Type          = 'DWord'
            AllowedValues = @(0, 1)
        },
        @{
            Name          = 'SpotlightLockScreenOverlay'
            Category      = 'Debloat'
            Description   = 'Windows Spotlight lock screen tips/ads overlay: 0 = off, 1 = on'
            Mechanism     = 'DefaultHive'
            Path          = 'SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
            ValueName     = 'RotatingLockScreenOverlayEnabled'
            Type          = 'DWord'
            AllowedValues = @(0, 1)
        },
        @{
            Name          = 'DefenderPrompt'
            Category      = 'Debloat'
            Description   = 'Windows Defender first-run prompt: 0 = suppress'
            Mechanism     = 'DefaultHive'
            Path          = 'SOFTWARE\Microsoft\Windows Defender'
            ValueName     = 'UifirstRun'
            Type          = 'DWord'
            AllowedValues = @(0)
        },
        @{
            Name          = 'FinishSettingUpPrompts'
            Category      = 'Debloat'
            Description   = 'Post-update "finish setting up your device" / backup prompts (SCOOBE): 0 = off, 1 = on'
            Mechanism     = 'DefaultHive'
            Path          = 'SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement'
            ValueName     = 'ScoobeSystemSettingEnabled'
            Type          = 'DWord'
            AllowedValues = @(0, 1)
        },
        @{
            Name          = 'AdvertisingId'
            Category      = 'Debloat'
            Description   = 'Advertising ID for app personalized ads: 0 = off, 1 = on'
            Mechanism     = 'DefaultHive'
            Path          = 'SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo'
            ValueName     = 'Enabled'
            Type          = 'DWord'
            AllowedValues = @(0, 1)
        },
        @{
            Name          = 'TailoredExperiences'
            Category      = 'Debloat'
            Description   = 'Personalized offers/tips from diagnostic data: 0 = off, 1 = on'
            Mechanism     = 'DefaultHive'
            Path          = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy'
            ValueName     = 'TailoredExperiencesWithDiagnosticDataEnabled'
            Type          = 'DWord'
            AllowedValues = @(0, 1)
        },
        @{
            Name          = 'FeedbackFrequency'
            Category      = 'Debloat'
            Description   = 'Windows feedback requests (Diagnostics & feedback > Feedback frequency): 0 = never'
            Mechanism     = 'DefaultHive'
            Path          = 'SOFTWARE\Microsoft\Siuf\Rules'
            ValueName     = 'NumberOfSIUFInPeriod'
            Type          = 'DWord'
            AllowedValues = @(0)
        },
        @{
            Name          = 'DesktopBackground'
            Category      = 'Debloat'
            Description   = 'Desktop background source: 0 = Picture, 3 = Windows Spotlight'
            Mechanism     = 'Custom'
            NeedsHive     = $true
            AllowedValues = @(0, 3)
        },
        @{
            Name        = 'OneDriveSetup'
            Category    = 'Debloat'
            Description = 'Remove the OneDrive first-run auto-setup from the default profile'
            Mechanism   = 'Custom'
            NeedsHive   = $true
        },
        @{
            Name        = 'RemoveOfficeApps'
            Category    = 'Debloat'
            Description = 'Uninstall pre-installed Microsoft 365 / OneNote stubs (Click-to-Run)'
            Mechanism   = 'Custom'
            NeedsHive   = $false
        },
        @{
            Name              = 'RemoveProvisionedApps'
            Category          = 'Debloat'
            Description       = 'Remove provisioned UWP apps. Config may override the list with an array.'
            Mechanism         = 'AppRemoval'
            PackageNames      = @(
                'Microsoft.BingNews',
                'Microsoft.GamingApp',
                'Microsoft.GetHelp',
                'Microsoft.MicrosoftSolitaireCollection',
                'Microsoft.WindowsFeedbackHub',
                'Microsoft.Windows.DevHome',
                'Microsoft.OutlookForWindows',
                'MSTeams'
            )
            AvailablePackages = @(
                'Clipchamp.Clipchamp',
                'Microsoft.BingNews',
                'Microsoft.BingWeather',
                'Microsoft.GamingApp',
                'Microsoft.GetHelp',
                'Microsoft.MicrosoftOfficeHub',
                'Microsoft.MicrosoftSolitaireCollection',
                'Microsoft.MicrosoftStickyNotes',
                'Microsoft.OutlookForWindows',
                'Microsoft.Paint',
                'Microsoft.PowerAutomateDesktop',
                'Microsoft.ScreenSketch',
                'Microsoft.Todos',
                'Microsoft.Windows.DevHome',
                'Microsoft.Windows.Photos',
                'Microsoft.WindowsAlarms',
                'Microsoft.WindowsCalculator',
                'Microsoft.WindowsCamera',
                'Microsoft.WindowsFeedbackHub',
                'Microsoft.WindowsNotepad',
                'Microsoft.WindowsSoundRecorder',
                'Microsoft.Xbox.TCUI',
                'Microsoft.XboxGamingOverlay',
                'Microsoft.XboxIdentityProvider',
                'Microsoft.XboxSpeechToTextOverlay',
                'Microsoft.YourPhone',
                'Microsoft.ZuneMusic',
                'MicrosoftCorporationII.QuickAssist',
                'MicrosoftWindows.Client.WebExperience',
                'MicrosoftWindows.CrossDevice',
                'MSTeams'
            )
        },

        # =========================== DEFAULT APPS (Dism) ====================================
        @{
            Name        = 'DefaultAppAssociations'
            Category    = 'DefaultApps'
            Description = 'Import default file/protocol associations (package\Assets\AppAssociations\AppAssociations.xml)'
            Mechanism   = 'Dism'
            Operation   = 'ImportDefaultAppAssociations'
            Source      = 'Assets\AppAssociations\AppAssociations.xml'
            AssetRoot   = 'DefaultAssociations'
        },

        # =========================== SYSTEM =================================================
        @{
            Name          = 'FastStartup'
            Category      = 'System'
            Description   = 'Fast Startup (hiberboot): 0 = disabled, 1 = enabled'
            Mechanism     = 'HKLM'
            Path          = 'SYSTEM\CurrentControlSet\Control\Session Manager\Power'
            ValueName     = 'HiberbootEnabled'
            Type          = 'DWord'
            AllowedValues = @(0, 1)
        },
        @{
            Name          = 'ClipboardHistory'
            Category      = 'System'
            Description   = 'Clipboard history (Win+V): 0 = off, 1 = on'
            Mechanism     = 'DefaultHive'
            Path          = 'Software\Microsoft\Clipboard'
            ValueName     = 'EnableClipboardHistory'
            Type          = 'DWord'
            AllowedValues = @(0, 1)
        },
        @{
            Name          = 'GameBarControllerButton'
            Category      = 'System'
            Description   = 'Open Game Bar with the controller Xbox button: 0 = off, 1 = on'
            Mechanism     = 'DefaultHive'
            Path          = 'SOFTWARE\Microsoft\GameBar'
            ValueName     = 'UseNexusForGameBarEnabled'
            Type          = 'DWord'
            AllowedValues = @(0, 1)
        },
        @{
            Name        = 'NetworkNotification'
            Category    = 'System'
            Description = 'Suppress the "new network location" flyout'
            Mechanism   = 'Custom'
            NeedsHive   = $false
        },
        @{
            Name        = 'EnableLocationServices'
            Category    = 'System'
            Description = 'Enable location services (machine consent). Prerequisite for DynamicTime.'
            Mechanism   = 'Custom'
            NeedsHive   = $false
        },
        @{
            Name        = 'DynamicTime'
            Category    = 'System'
            Description = 'Set the time zone automatically (requires EnableLocationServices)'
            Mechanism   = 'Custom'
            NeedsHive   = $false
            DependsOn   = 'EnableLocationServices'
        },

        # =========================== ACCESSIBILITY (Custom) =================================
        @{
            Name          = 'StickyKeysShortcut'
            Category      = 'Accessibility'
            Description   = 'Sticky Keys keyboard shortcut (press Shift 5 times): 0 = off, 1 = on'
            Mechanism     = 'Custom'
            NeedsHive     = $true
            AllowedValues = @(0, 1)
        },

        # =========================== BRANDING (Custom: takeown + replace) ===================
        @{
            Name        = 'DesktopWallpaper'
            Category    = 'Branding'
            Description = 'Replace the default light and dark desktop wallpapers (package\Assets\Branding\img0.jpg, optional img19.jpg, + 4k\)'
            Mechanism   = 'Custom'
            NeedsHive   = $false
        },
        @{
            Name        = 'LockScreenImage'
            Category    = 'Branding'
            Description = 'Replace the default lock screen image (package\Assets\Branding\img100.jpg)'
            Mechanism   = 'Custom'
            NeedsHive   = $false
        },

        # =========================== FILE SEEDS (default profile) ===========================
        @{
            Name        = 'TaskbarPins'
            Category    = 'Taskbar'
            Description = 'Seed default taskbar pins (user can still change them)'
            Mechanism   = 'File'
            Source      = 'Assets\Layout\LayoutModification.xml'
            AssetRoot   = 'LayoutModificationTemplate'
            Destination = '%SystemDrive%\Users\Default\AppData\Local\Microsoft\Windows\Shell\LayoutModification.xml'
        },
        @{
            Name        = 'StartLayout'
            Category    = 'Start'
            Description = 'Seed default Start menu layout (start2.bin)'
            Mechanism   = 'File'
            Source      = 'Assets\Layout\start2.bin'
            Destination = '%SystemDrive%\Users\Default\AppData\Local\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState\start2.bin'
        },

        # =========================== LOCKING SETTINGS (Policy; off by default) ==============
        @{
            Name          = 'EdgeFirstRun'
            Category      = 'Debloat'
            Description   = 'Suppress Edge first-run experience.'
            Mechanism     = 'Policy'
            Path          = 'SOFTWARE\Policies\Microsoft\Edge'
            ValueName     = 'HideFirstRunExperience'
            Type          = 'DWord'
            AllowedValues = @(1)
        },
        @{
            Name          = 'OOBEPrivacyExperience'
            Category      = 'Debloat'
            Description   = 'Skip the OOBE privacy-settings page.'
            Mechanism     = 'Policy'
            Path          = 'SOFTWARE\Policies\Microsoft\Windows\OOBE'
            ValueName     = 'DisablePrivacyExperience'
            Type          = 'DWord'
            AllowedValues = @(1)
        },
        @{
            Name          = 'FirstLogonAnimation'
            Category      = 'System'
            Description   = 'First-logon animation (machine policy): 0 = off, 1 = on'
            Mechanism     = 'Policy'
            Path          = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueName     = 'EnableFirstLogonAnimation'
            Type          = 'DWord'
            AllowedValues = @(0, 1)
        },
        @{
            Name          = 'WidgetsButton'
            Category      = 'Taskbar'
            Description   = 'Widgets button (machine policy): 0 = hidden, 1 = shown'
            Mechanism     = 'Policy'
            Path          = 'SOFTWARE\Policies\Microsoft\Dsh'
            ValueName     = 'AllowNewsAndInterests'
            Type          = 'DWord'
            AllowedValues = @(0, 1)
        }
    )
}
