```sql
// Translated content (automatically translated on 24-08-2025 01:52:16):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\updatepolicy.dll" and (not (module.path in ("c:\\windows\\system32\*","c:\\windows\\syswow64\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of updatepolicy.dll
id: 4486711b-9395-48a3-4833-5b9ff8668728
status: experimental
description: Detects possible DLL hijacking of updatepolicy.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/updatepolicy.html
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
        ImageLoaded: '*\updatepolicy.dll'
    filter:
        ImageLoaded:
            - 'c:\windows\system32\*'
            - 'c:\windows\syswow64\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
