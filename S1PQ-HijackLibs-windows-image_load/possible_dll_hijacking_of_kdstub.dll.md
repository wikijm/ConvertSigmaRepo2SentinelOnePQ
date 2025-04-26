```sql
// Translated content (automatically translated on 26-04-2025 10:11:02):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\kdstub.dll" and (not module.path="c:\windows\system32\*")))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of kdstub.dll
id: 5724121b-9395-48a3-4833-5b9ff8416715
status: experimental
description: Detects possible DLL hijacking of kdstub.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/kdstub.html
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
        ImageLoaded: '*\kdstub.dll'
    filter:
        ImageLoaded:
            - 'c:\windows\system32\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
