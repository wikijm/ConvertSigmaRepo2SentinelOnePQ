```sql
// Translated content (automatically translated on 12-06-2025 01:47:24):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\profapi.dll" and (not (module.path in ("c:\windows\system32\*","c:\windows\syswow64\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of profapi.dll
id: 3508431b-2028-48a3-1241-5b9ff8610394
status: experimental
description: Detects possible DLL hijacking of profapi.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/profapi.html
author: "Chris Spehn"
date: 2021-08-16
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\profapi.dll'
    filter:
        ImageLoaded:
            - 'c:\windows\system32\*'
            - 'c:\windows\syswow64\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
