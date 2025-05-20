```sql
// Translated content (automatically translated on 20-05-2025 01:46:22):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\msctf.dll" and (not (module.path in ("c:\windows\system32\*","c:\windows\syswow64\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of msctf.dll
id: 7893481b-2897-48a3-6541-5b9ff8843696
status: experimental
description: Detects possible DLL hijacking of msctf.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/msctf.html
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
        ImageLoaded: '*\msctf.dll'
    filter:
        ImageLoaded:
            - 'c:\windows\system32\*'
            - 'c:\windows\syswow64\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
