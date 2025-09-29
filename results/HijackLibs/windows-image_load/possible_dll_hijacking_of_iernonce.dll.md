```sql
// Translated content (automatically translated on 29-09-2025 01:40:13):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\iernonce.dll" and (not (module.path in ("c:\\windows\\system32\*","c:\\windows\\syswow64\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of iernonce.dll
id: 8055051b-8657-48a3-9976-5b9ff8164533
status: experimental
description: Detects possible DLL hijacking of iernonce.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/iernonce.html
author: "Wietze Beukema"
date: 2024-01-11
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\iernonce.dll'
    filter:
        ImageLoaded:
            - 'c:\windows\system32\*'
            - 'c:\windows\syswow64\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
