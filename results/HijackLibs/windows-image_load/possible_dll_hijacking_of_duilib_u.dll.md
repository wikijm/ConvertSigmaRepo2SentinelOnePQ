```sql
// Translated content (automatically translated on 22-12-2025 01:56:59):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\duilib_u.dll" and (not (module.path in ("c:\\program files\\AnyViewer\*","c:\\program files (x86)\\AnyViewer\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of duilib_u.dll
id: 5096711b-7808-48a3-6638-5b9ff8715589
status: experimental
description: Detects possible DLL hijacking of duilib_u.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/anyviewer/duilib_u.html
author: "Jose Oregon"
date: 2025-04-29
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\duilib_u.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\AnyViewer\*'
            - 'c:\program files (x86)\AnyViewer\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
