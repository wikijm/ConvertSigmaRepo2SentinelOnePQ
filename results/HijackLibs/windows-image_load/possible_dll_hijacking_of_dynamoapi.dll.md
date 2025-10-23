```sql
// Translated content (automatically translated on 23-10-2025 01:40:31):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\dynamoapi.dll" and (not module.path="c:\\windows\\system32\*")))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of dynamoapi.dll
id: 5174911b-9395-48a3-4833-5b9ff8133347
status: experimental
description: Detects possible DLL hijacking of dynamoapi.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/dynamoapi.html
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
        ImageLoaded: '*\dynamoapi.dll'
    filter:
        ImageLoaded:
            - 'c:\windows\system32\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
