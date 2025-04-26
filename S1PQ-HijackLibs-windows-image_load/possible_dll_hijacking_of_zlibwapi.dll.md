```sql
// Translated content (automatically translated on 26-04-2025 10:11:02):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\zlibwapi.dll" and (not (module.path in ("c:\program files\DS Clock\*","c:\program files (x86)\DS Clock\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of zlibwapi.dll
id: 5449341b-9910-48a3-3013-5b9ff8401940
status: experimental
description: Detects possible DLL hijacking of zlibwapi.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/zlib/zlibwapi.html
author: "Still Hsu"
date: 2024-11-24
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\zlibwapi.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\DS Clock\*'
            - 'c:\program files (x86)\DS Clock\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
