```sql
// Translated content (automatically translated on 03-07-2025 00:53:49):
event.category="Registry" and (endpoint.os="windows" and (registry.keyPath contains "HKLM\SOFTWARE\TeamViewer\*" or registry.keyPath contains "HKU\<SID>\SOFTWARE\TeamViewer\*" or registry.keyPath contains "HKLM\SYSTEM\CurrentControlSet\Services\TeamViewer\*" or registry.keyPath contains "HKLM\SOFTWARE\TeamViewer\ConnectionHistory" or registry.keyPath contains "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\TeamViewer\*" or registry.keyPath contains "HKU\SID\SOFTWARE\TeamViewer\MainWindowHandle" or registry.keyPath contains "HKU\SID\SOFTWARE\TeamViewer\DesktopWallpaperSingleImage" or registry.keyPath contains "HKU\SID\SOFTWARE\TeamViewer\DesktopWallpaperSingleImagePath" or registry.keyPath contains "HKU\SID\SOFTWARE\TeamViewer\DesktopWallpaperSingleImagePosition" or registry.keyPath contains "HKU\SID\SOFTWARE\TeamViewer\MinimizeToTray" or registry.keyPath contains "HKU\SID\SOFTWARE\TeamViewer\MultiMedia\AudioUserSelectedCapturingEndpoint" or registry.keyPath contains "HKU\SID\SOFTWARE\TeamViewer\MultiMedia\AudioSendingVolumeV2" or registry.keyPath contains "HKU\SID\SOFTWARE\TeamViewer\MultiMedia\AudioUserSelectedRenderingEndpoint" or registry.keyPath contains "HKLM\SOFTWARE\TeamViewer\ConnectionHistory" or registry.keyPath contains "HKU\SID\SOFTWARE\TeamViewer\ClientWindow_Mode" or registry.keyPath contains "HKU\SID\SOFTWARE\TeamViewer\ClientWindowPositions"))
```


# Original Sigma Rule:
```yaml
title: Potential TeamViewer RMM Tool Registry Activity
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
id: 8bc53048-ffad-4f92-9b66-a75d19e9dde9
status: experimental
description: Detects potential registry activity of TeamViewer RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of TeamViewer
level: medium
```
