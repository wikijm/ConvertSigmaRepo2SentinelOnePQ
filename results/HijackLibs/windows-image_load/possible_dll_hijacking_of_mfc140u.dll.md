```sql
// Translated content (automatically translated on 22-12-2025 01:56:59):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\mfc140u.dll" and (not (module.path in ("c:\\program files\\CheckMAL\\AppCheck\*","c:\\program files (x86)\\CheckMAL\\AppCheck\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of mfc140u.dll
id: 3650591b-3546-48a3-3513-5b9ff8400652
status: experimental
description: Detects possible DLL hijacking of mfc140u.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/checkmal/mfc140u.html
author: "Jai Minton - HuntressLabs"
date: 2025-02-19
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\mfc140u.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\CheckMAL\AppCheck\*'
            - 'c:\program files (x86)\CheckMAL\AppCheck\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
