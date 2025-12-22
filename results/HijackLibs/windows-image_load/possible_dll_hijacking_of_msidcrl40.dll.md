```sql
// Translated content (automatically translated on 22-12-2025 01:56:59):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\msidcrl40.dll" and (not (module.path in ("c:\\program files\\msn messenger\*","c:\\program files (x86)\\msn messenger\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of msidcrl40.dll
id: 2253401b-4592-48a3-2807-5b9ff8762429
status: experimental
description: Detects possible DLL hijacking of msidcrl40.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/external/msidcrl40.html
author: "Jai Minton - HuntressLabs"
date: 2024-05-29
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\msidcrl40.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\msn messenger\*'
            - 'c:\program files (x86)\msn messenger\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
