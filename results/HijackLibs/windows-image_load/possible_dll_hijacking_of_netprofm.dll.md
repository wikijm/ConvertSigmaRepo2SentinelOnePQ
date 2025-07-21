```sql
// Translated content (automatically translated on 21-07-2025 02:01:39):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\netprofm.dll" and (not (module.path in ("c:\windows\system32\*","c:\windows\syswow64\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of netprofm.dll
id: 8642451b-2897-48a3-6541-5b9ff8920546
status: experimental
description: Detects possible DLL hijacking of netprofm.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/netprofm.html
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
        ImageLoaded: '*\netprofm.dll'
    filter:
        ImageLoaded:
            - 'c:\windows\system32\*'
            - 'c:\windows\syswow64\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
