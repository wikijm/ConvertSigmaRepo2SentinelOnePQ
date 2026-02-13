```sql
// Translated content (automatically translated on 13-02-2026 02:32:00):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\libsmartscreenn.dll" and (not (module.path="c:\\program files\\WindowsApps\\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe\*" or module.path="c:\\program files (x86)\\WindowsApps\\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe\*"))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of libsmartscreenn.dll
id: 8778331b-2788-48a3-7807-5b9ff8401123
status: experimental
description: Detects possible DLL hijacking of libsmartscreenn.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/libsmartscreenn.html
author: "Still Hsu"
date: 2025-12-12
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\libsmartscreenn.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe\*'
            - 'c:\program files (x86)\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
