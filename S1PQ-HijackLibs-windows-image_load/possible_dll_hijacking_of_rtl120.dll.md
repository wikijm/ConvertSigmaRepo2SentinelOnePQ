```sql
// Translated content (automatically translated on 26-04-2025 10:11:02):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\rtl120.dll" and (not (module.path in ("c:\program files\DualSafe Password Manager\*","c:\program files (x86)\DualSafe Password Manager\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of rtl120.dll
id: 1106121b-1146-48a3-9461-5b9ff8861492
status: experimental
description: Detects possible DLL hijacking of rtl120.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/itop/rtl120.html
author: "Jai Minton - HuntressLabs"
date: 2024-06-14
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\rtl120.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\DualSafe Password Manager\*'
            - 'c:\program files (x86)\DualSafe Password Manager\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
