```sql
// Translated content (automatically translated on 27-08-2025 01:40:13):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\pla.dll" and (not (module.path in ("c:\\windows\\system32\*","c:\\windows\\syswow64\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of pla.dll
id: 2941911b-2897-48a3-6541-5b9ff8972273
status: experimental
description: Detects possible DLL hijacking of pla.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/pla.html
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
        ImageLoaded: '*\pla.dll'
    filter:
        ImageLoaded:
            - 'c:\windows\system32\*'
            - 'c:\windows\syswow64\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
