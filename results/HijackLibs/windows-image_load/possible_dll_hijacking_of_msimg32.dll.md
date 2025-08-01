```sql
// Translated content (automatically translated on 02-08-2025 01:52:58):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\msimg32.dll" and (not (module.path in ("c:\program files\Haihaisoft PDF Reader\*","c:\program files (x86)\Haihaisoft PDF Reader\*","c:\windows\system32\*","c:\windows\syswow64\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of msimg32.dll
id: 7330221b-4026-48a3-2477-5b9ff8149851
status: experimental
description: Detects possible DLL hijacking of msimg32.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/external/msimg32.html
author: "Jai Minton - HuntressLabs"
date: 2025-04-10
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\msimg32.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Haihaisoft PDF Reader\*'
            - 'c:\program files (x86)\Haihaisoft PDF Reader\*'
            - 'c:\windows\system32\*'
            - 'c:\windows\syswow64\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
