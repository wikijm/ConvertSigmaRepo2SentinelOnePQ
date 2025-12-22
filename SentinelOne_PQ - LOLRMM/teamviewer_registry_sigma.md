```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.category="registry" and (endpoint.os="windows" and (registry.keyPath contains "HKLM\\SOFTWARE\\TeamViewer\*" or registry.keyPath contains "HKU\\<SID>\\SOFTWARE\\TeamViewer\*" or registry.keyPath contains "HKLM\\SYSTEM\\CurrentControlSet\\Services\\TeamViewer\*" or registry.keyPath contains "HKLM\\SOFTWARE\\TeamViewer\\ConnectionHistory" or registry.keyPath contains "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\TeamViewer\*" or registry.keyPath contains "HKU\\SID\\SOFTWARE\\TeamViewer\\MainWindowHandle" or registry.keyPath contains "HKU\\SID\\SOFTWARE\\TeamViewer\\DesktopWallpaperSingleImage" or registry.keyPath contains "HKU\\SID\\SOFTWARE\\TeamViewer\\DesktopWallpaperSingleImagePath" or registry.keyPath contains "HKU\\SID\\SOFTWARE\\TeamViewer\\DesktopWallpaperSingleImagePosition" or registry.keyPath contains "HKU\\SID\\SOFTWARE\\TeamViewer\\MinimizeToTray" or registry.keyPath contains "HKU\\SID\\SOFTWARE\\TeamViewer\\MultiMedia\\AudioUserSelectedCapturingEndpoint" or registry.keyPath contains "HKU\\SID\\SOFTWARE\\TeamViewer\\MultiMedia\\AudioSendingVolumeV2" or registry.keyPath contains "HKU\\SID\\SOFTWARE\\TeamViewer\\MultiMedia\\AudioUserSelectedRenderingEndpoint" or registry.keyPath contains "HKLM\\SOFTWARE\\TeamViewer\\ConnectionHistory" or registry.keyPath contains "HKU\\SID\\SOFTWARE\\TeamViewer\\ClientWindow_Mode" or registry.keyPath contains "HKU\\SID\\SOFTWARE\\TeamViewer\\ClientWindowPositions"))
```


# Original Sigma Rule:
```yaml
title: Potential TeamViewer RMM Tool Registry Activity
id: 6673bb39-482d-4b90-8ab2-a3ad594eb5eb
status: experimental
description: |
    Detects potential registry activity of TeamViewer RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2025-12-01
tags:
    - attack.execution
    - attack.t1219
logsource:
    product: windows
    category: registry_event
detection:
    selection:
        TargetObject|contains:
            - HKLM\SOFTWARE\TeamViewer\*
            - HKU\<SID>\SOFTWARE\TeamViewer\*
            - HKLM\SYSTEM\CurrentControlSet\Services\TeamViewer\*
            - HKLM\SOFTWARE\TeamViewer\ConnectionHistory
            - HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\TeamViewer\*
            - HKU\SID\SOFTWARE\TeamViewer\MainWindowHandle
            - HKU\SID\SOFTWARE\TeamViewer\DesktopWallpaperSingleImage
            - HKU\SID\SOFTWARE\TeamViewer\DesktopWallpaperSingleImagePath
            - HKU\SID\SOFTWARE\TeamViewer\DesktopWallpaperSingleImagePosition
            - HKU\SID\SOFTWARE\TeamViewer\MinimizeToTray
            - HKU\SID\SOFTWARE\TeamViewer\MultiMedia\AudioUserSelectedCapturingEndpoint
            - HKU\SID\SOFTWARE\TeamViewer\MultiMedia\AudioSendingVolumeV2
            - HKU\SID\SOFTWARE\TeamViewer\MultiMedia\AudioUserSelectedRenderingEndpoint
            - HKLM\SOFTWARE\TeamViewer\ConnectionHistory
            - HKU\SID\SOFTWARE\TeamViewer\ClientWindow_Mode
            - HKU\SID\SOFTWARE\TeamViewer\ClientWindowPositions
    condition: selection
falsepositives:
    - Legitimate use of TeamViewer
level: medium
```
