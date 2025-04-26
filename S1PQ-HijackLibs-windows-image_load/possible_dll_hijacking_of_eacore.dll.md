```sql
// Translated content (automatically translated on 26-04-2025 10:11:02):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\eacore.dll" and (not (module.path in ("c:\program files\Electronic Arts\EA Desktop\EA Desktop\*","c:\program files (x86)\Electronic Arts\EA Desktop\EA Desktop\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of eacore.dll
id: 9683001b-8907-48a3-9464-5b9ff8957682
status: experimental
description: Detects possible DLL hijacking of eacore.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/electronicarts/eacore.html
author: "Wietze Beukema"
date: 2025-02-15
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\eacore.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Electronic Arts\EA Desktop\EA Desktop\*'
            - 'c:\program files (x86)\Electronic Arts\EA Desktop\EA Desktop\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
