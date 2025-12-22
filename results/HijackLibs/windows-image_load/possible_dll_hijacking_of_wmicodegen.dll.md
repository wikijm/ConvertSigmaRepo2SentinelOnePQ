```sql
// Translated content (automatically translated on 22-12-2025 01:56:59):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\wmicodegen.dll" and (not (module.path in ("c:\\program files\\windows kits\*\\bin\*\*","c:\\program files (x86)\\windows kits\*\\bin\*\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of wmicodegen.dll
id: 2340121b-6939-48a3-6071-5b9ff8311072
status: experimental
description: Detects possible DLL hijacking of wmicodegen.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/external/wmicodegen.html
author: "Swachchhanda Shrawan Poudel"
date: 2024-07-25
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\wmicodegen.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\windows kits\*\bin\*\*'
            - 'c:\program files (x86)\windows kits\*\bin\*\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.
```
