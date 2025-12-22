```sql
// Translated content (automatically translated on 22-12-2025 01:56:59):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\hha.dll" and (not (module.path in ("c:\\windows\\system32\*","c:\\windows\\syswow64\*","c:\\program files\\HTML Help Workshop\*","c:\\program files (x86)\\HTML Help Workshop\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of hha.dll
id: 6370911b-6722-48a3-2305-5b9ff8430460
status: experimental
description: Detects possible DLL hijacking of hha.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/external/hha.html
author: "Wietze Beukema"
date: 2021-12-08
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\hha.dll'
    filter:
        ImageLoaded:
            - 'c:\windows\system32\*'
            - 'c:\windows\syswow64\*'
            - 'c:\program files\HTML Help Workshop\*'
            - 'c:\program files (x86)\HTML Help Workshop\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
