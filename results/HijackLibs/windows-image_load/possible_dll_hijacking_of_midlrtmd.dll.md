```sql
// Translated content (automatically translated on 28-02-2026 02:04:27):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\midlrtmd.dll" and (not (module.path="c:\\program files\\Windows Kits\\*\\bin\\*\\x64\\mdmerge.exe\\*" or module.path="c:\\program files (x86)\\Windows Kits\\*\\bin\\*\\x64\\mdmerge.exe\\*" or module.path="c:\\program files\\Windows Kits\\*\\bin\\*\\x86\\mdmerge.exe\\*" or module.path="c:\\program files (x86)\\Windows Kits\\*\\bin\\*\\x86\\mdmerge.exe\\*"))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of midlrtmd.dll
id: 4697261b-1497-48a3-1258-5b9ff8380603
status: experimental
description: Detects possible DLL hijacking of midlrtmd.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/external/midlrtmd.html
author: "Rick Gatenby"
date: 2026-02-03
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\midlrtmd.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Windows Kits\\*\bin\\*\x64\mdmerge.exe\\*'
            - 'c:\program files (x86)\Windows Kits\\*\bin\\*\x64\mdmerge.exe\\*'
            - 'c:\program files\Windows Kits\\*\bin\\*\x86\mdmerge.exe\\*'
            - 'c:\program files (x86)\Windows Kits\\*\bin\\*\x86\mdmerge.exe\\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
