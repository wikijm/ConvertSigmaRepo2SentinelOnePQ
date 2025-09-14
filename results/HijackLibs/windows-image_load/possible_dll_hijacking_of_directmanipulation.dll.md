```sql
// Translated content (automatically translated on 14-09-2025 01:41:51):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\directmanipulation.dll" and (not (module.path in ("c:\\windows\\system32\*","c:\\windows\\syswow64\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of directmanipulation.dll
id: 5855901b-3713-48a3-9900-5b9ff8898085
status: experimental
description: Detects possible DLL hijacking of directmanipulation.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/directmanipulation.html
author: "Wietze Beukema"
date: 2022-08-14
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\directmanipulation.dll'
    filter:
        ImageLoaded:
            - 'c:\windows\system32\*'
            - 'c:\windows\syswow64\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
