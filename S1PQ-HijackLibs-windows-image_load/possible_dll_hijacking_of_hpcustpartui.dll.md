```sql
// Translated content (automatically translated on 26-04-2025 10:11:02):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\hpcustpartui.dll" and (not (module.path in ("c:\program files\HP\*","c:\program files (x86)\HP\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of hpcustpartui.dll
id: 3589891b-8743-48a3-3543-5b9ff8444314
status: experimental
description: Detects possible DLL hijacking of hpcustpartui.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/hp/hpcustpartui.html
author: "Christiaan Beek"
date: 2023-01-10
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\hpcustpartui.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\HP\*'
            - 'c:\program files (x86)\HP\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
