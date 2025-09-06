```sql
// Translated content (automatically translated on 06-09-2025 01:27:09):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\iumsdk.dll" and (not module.path="c:\\windows\\system32\*")))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of iumsdk.dll
id: 5717571b-2028-48a3-1241-5b9ff8424484
status: experimental
description: Detects possible DLL hijacking of iumsdk.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/iumsdk.html
author: "Chris Spehn"
date: 2021-08-16
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\iumsdk.dll'
    filter:
        ImageLoaded:
            - 'c:\windows\system32\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
