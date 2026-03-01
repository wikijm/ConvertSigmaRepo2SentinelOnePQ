```sql
// Translated content (automatically translated on 01-03-2026 02:34:34):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\vcruntime140.dll" and (not module.path contains "c:\\windows\\system32\\")))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of vcruntime140.dll
id: 1697281b-3028-48a3-8802-5b9ff8136955
status: experimental
description: Detects possible DLL hijacking of vcruntime140.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/vcruntime140.html
author: "Swachchhanda Shrawan Poudel"
date: 2026-01-06
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\vcruntime140.dll'
    filter:
        ImageLoaded:
            - 'c:\windows\system32\\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
