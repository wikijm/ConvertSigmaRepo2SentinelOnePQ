```sql
// Translated content (automatically translated on 09-07-2025 01:51:23):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\msxml3.dll" and (not (module.path in ("c:\windows\system32\*","c:\windows\syswow64\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of msxml3.dll
id: 8921941b-2897-48a3-6541-5b9ff8888889
status: experimental
description: Detects possible DLL hijacking of msxml3.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/msxml3.html
author: "Wietze Beukema"
date: 2022-05-21
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\msxml3.dll'
    filter:
        ImageLoaded:
            - 'c:\windows\system32\*'
            - 'c:\windows\syswow64\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
