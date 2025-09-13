```sql
// Translated content (automatically translated on 13-09-2025 01:23:25):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\peerdistsh.dll" and (not (module.path in ("c:\\windows\\system32\*","c:\\windows\\syswow64\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of peerdistsh.dll
id: 3482931b-9395-48a3-4833-5b9ff8816370
status: experimental
description: Detects possible DLL hijacking of peerdistsh.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/peerdistsh.html
author: "Wietze Beukema"
date: 2021-02-27
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\peerdistsh.dll'
    filter:
        ImageLoaded:
            - 'c:\windows\system32\*'
            - 'c:\windows\syswow64\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
