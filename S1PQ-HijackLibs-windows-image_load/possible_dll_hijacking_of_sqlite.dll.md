```sql
// Translated content (automatically translated on 26-04-2025 10:11:02):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\sqlite.dll" and (not (module.path in ("c:\program files\NetWorx\*","c:\program files (x86)\NetWorx\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of sqlite.dll
id: 5920601b-6171-48a3-7472-5b9ff8606319
status: experimental
description: Detects possible DLL hijacking of sqlite.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/softperfect/sqlite.html
author: "Jai Minton - HuntressLabs"
date: 2024-05-06
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\sqlite.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\NetWorx\*'
            - 'c:\program files (x86)\NetWorx\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
