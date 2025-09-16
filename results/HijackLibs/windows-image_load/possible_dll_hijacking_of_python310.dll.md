```sql
// Translated content (automatically translated on 16-09-2025 01:27:46):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\python310.dll" and (not (module.path in ("c:\\program files\\Python310\*","c:\\program files (x86)\\Python310\*","c:\\users\*\\appdata\\local\\Temp\*\*","c:\\program files\\DWAgent\\runtime\*","c:\\program files (x86)\\DWAgent\\runtime\*","%USERPROFILE%\\anaconda3\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of python310.dll
id: 6631001b-7990-48a3-2194-5b9ff8874886
status: experimental
description: Detects possible DLL hijacking of python310.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/python/python310.html
author: "Jai Minton"
date: 2024-05-08
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\python310.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Python310\*'
            - 'c:\program files (x86)\Python310\*'
            - 'c:\users\*\appdata\local\Temp\*\*'
            - 'c:\program files\DWAgent\runtime\*'
            - 'c:\program files (x86)\DWAgent\runtime\*'
            - '%USERPROFILE%\anaconda3\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
