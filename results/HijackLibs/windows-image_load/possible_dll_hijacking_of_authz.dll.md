```sql
// Translated content (automatically translated on 01-10-2025 01:47:01):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\authz.dll" and (not (module.path in ("c:\\windows\\system32\*","c:\\windows\\syswow64\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of authz.dll
id: 9309811b-9395-48a3-4833-5b9ff8476213
status: experimental
description: Detects possible DLL hijacking of authz.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/authz.html
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
        ImageLoaded: '*\authz.dll'
    filter:
        ImageLoaded:
            - 'c:\windows\system32\*'
            - 'c:\windows\syswow64\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
