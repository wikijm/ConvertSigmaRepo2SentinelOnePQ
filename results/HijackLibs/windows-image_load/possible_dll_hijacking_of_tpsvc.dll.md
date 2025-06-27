```sql
// Translated content (automatically translated on 27-06-2025 01:49:43):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\tpsvc.dll" and (not (module.path in ("c:\program files\VMWare\VMWare Tools\*","c:\program files (x86)\VMWare\VMWare Tools\*","c:\program files\Common Files\ThinPrint\*","c:\program files (x86)\Common Files\ThinPrint\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of tpsvc.dll
id: 1712241b-9569-48a3-1936-5b9ff8544276
status: experimental
description: Detects possible DLL hijacking of tpsvc.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/thinprint/tpsvc.html
author: "Jai Minton - HuntressLabs"
date: 2024-04-15
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\tpsvc.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\VMWare\VMWare Tools\*'
            - 'c:\program files (x86)\VMWare\VMWare Tools\*'
            - 'c:\program files\Common Files\ThinPrint\*'
            - 'c:\program files (x86)\Common Files\ThinPrint\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
