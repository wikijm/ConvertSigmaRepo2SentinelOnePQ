```sql
// Translated content (automatically translated on 02-08-2025 01:52:58):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\msedgeupdate.dll" and (not (module.path in ("c:\program files\Microsoft\EdgeUpdate\*\*","c:\program files (x86)\Microsoft\EdgeUpdate\*\*","c:\program files\Microsoft\Temp\*\*","c:\program files (x86)\Microsoft\Temp\*\*","c:\users\*\appdata\local\Microsoft\EdgeUpdate\*\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of msedgeupdate.dll
id: 9488221b-6363-48a3-2268-5b9ff8261094
status: experimental
description: Detects possible DLL hijacking of msedgeupdate.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/msedgeupdate.html
author: "Still Hsu"
date: 2024-05-26
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\msedgeupdate.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Microsoft\EdgeUpdate\*\*'
            - 'c:\program files (x86)\Microsoft\EdgeUpdate\*\*'
            - 'c:\program files\Microsoft\Temp\*\*'
            - 'c:\program files (x86)\Microsoft\Temp\*\*'
            - 'c:\users\*\appdata\local\Microsoft\EdgeUpdate\*\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
