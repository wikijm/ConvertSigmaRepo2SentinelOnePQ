```sql
// Translated content (automatically translated on 07-09-2025 01:42:20):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\isv.exe_rsaenh.dll" and (not (module.path in ("c:\\windows\\system32\*","c:\\windows\\syswow64\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of isv.exe_rsaenh.dll
id: 2823561b-2897-48a3-6541-5b9ff8886240
status: experimental
description: Detects possible DLL hijacking of isv.exe_rsaenh.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/isv.exe_rsaenh.html
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
        ImageLoaded: '*\isv.exe_rsaenh.dll'
    filter:
        ImageLoaded:
            - 'c:\windows\system32\*'
            - 'c:\windows\syswow64\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
