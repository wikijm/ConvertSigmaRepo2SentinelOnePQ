```sql
// Translated content (automatically translated on 22-12-2025 01:56:59):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\tutil32.dll" and (not (module.path in ("c:\\program files\\PDE\*","c:\\program files (x86)\\PDE\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of tutil32.dll
id: 4335961b-9675-48a3-8026-5b9ff8245961
status: experimental
description: Detects possible DLL hijacking of tutil32.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/mitec/tutil32.html
author: "Jai Minton"
date: 2025-05-06
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\tutil32.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\PDE\*'
            - 'c:\program files (x86)\PDE\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
