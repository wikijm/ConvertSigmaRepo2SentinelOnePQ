```sql
// Translated content (automatically translated on 06-08-2025 01:59:31):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\upshared.dll" and (not module.path="c:\\windows\\system32\*")))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of upshared.dll
id: 7075411b-9395-48a3-4833-5b9ff8955080
status: experimental
description: Detects possible DLL hijacking of upshared.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/upshared.html
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
        ImageLoaded: '*\upshared.dll'
    filter:
        ImageLoaded:
            - 'c:\windows\system32\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
