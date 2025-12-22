```sql
// Translated content (automatically translated on 22-12-2025 01:56:59):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\cryptnet.dll" and (not (module.path in ("c:\\windows\\system32\*","c:\\windows\\syswow64\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of cryptnet.dll
id: 6024931b-8091-48a3-6555-5b9ff8476279
status: experimental
description: Detects possible DLL hijacking of cryptnet.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/cryptnet.html
author: "Will Summerhill"
date: 2024-11-22
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\cryptnet.dll'
    filter:
        ImageLoaded:
            - 'c:\windows\system32\*'
            - 'c:\windows\syswow64\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
