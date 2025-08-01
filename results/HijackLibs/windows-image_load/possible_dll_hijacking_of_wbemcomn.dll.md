```sql
// Translated content (automatically translated on 02-08-2025 01:52:58):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\wbemcomn.dll" and (not (module.path in ("c:\windows\system32\*","c:\windows\syswow64\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of wbemcomn.dll
id: 3394111b-8283-48a3-9712-5b9ff8744436
status: experimental
description: Detects possible DLL hijacking of wbemcomn.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/wbemcomn.html
author: "v1stra"
date: 2024-12-12
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\wbemcomn.dll'
    filter:
        ImageLoaded:
            - 'c:\windows\system32\*'
            - 'c:\windows\syswow64\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
