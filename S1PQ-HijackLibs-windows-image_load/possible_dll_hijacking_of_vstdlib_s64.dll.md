```sql
// Translated content (automatically translated on 26-04-2025 10:11:02):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\vstdlib_s64.dll" and (not (module.path in ("c:\program files\Steam\*","c:\program files (x86)\Steam\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of vstdlib_s64.dll
id: 3565761b-3925-48a3-9336-5b9ff8162355
status: experimental
description: Detects possible DLL hijacking of vstdlib_s64.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/valve/vstdlib_s64.html
author: "Still Hsu"
date: 2024-09-24
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\vstdlib_s64.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Steam\*'
            - 'c:\program files (x86)\Steam\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
