```sql
// Translated content (automatically translated on 27-09-2025 01:26:03):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\libsqlite3-0.dll" and (not (module.path in ("c:\\program files\*","c:\\program files (x86)\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of libsqlite3-0.dll
id: 2620601b-3119-48a3-1242-5b9ff8266048
status: experimental
description: Detects possible DLL hijacking of libsqlite3-0.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/sqlite/libsqlite3-0.html
author: "Swachchhanda Shrawan Poudel"
date: 2025-07-12
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\libsqlite3-0.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\*'
            - 'c:\program files (x86)\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
