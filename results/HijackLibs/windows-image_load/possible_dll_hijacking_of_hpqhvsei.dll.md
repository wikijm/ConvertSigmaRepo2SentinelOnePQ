```sql
// Translated content (automatically translated on 22-12-2025 01:56:59):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\hpqhvsei.dll" and (not (module.path in ("c:\\program files\\HP\*","c:\\program files (x86)\\HP\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of hpqhvsei.dll
id: 9170171b-1995-48a3-3467-5b9ff8750947
status: experimental
description: Detects possible DLL hijacking of hpqhvsei.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/hp/hpqhvsei.html
author: "Wietze Beukema"
date: 2023-02-26
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\hpqhvsei.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\HP\*'
            - 'c:\program files (x86)\HP\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
