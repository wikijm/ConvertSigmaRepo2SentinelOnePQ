```sql
// Translated content (automatically translated on 26-04-2025 10:11:02):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\atl71.dll" and (not (module.path in ("c:\program files\Common Files\Thunder Network\TP\*\*","c:\program files (x86)\Common Files\Thunder Network\TP\*\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of atl71.dll
id: 6552891b-3685-48a3-9733-5b9ff8142648
status: experimental
description: Detects possible DLL hijacking of atl71.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/xunlei/atl71.html
author: "Jai Minton - HuntressLabs"
date: 2024-08-30
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\atl71.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Common Files\Thunder Network\TP\*\*'
            - 'c:\program files (x86)\Common Files\Thunder Network\TP\*\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
