```sql
// Translated content (automatically translated on 26-04-2025 10:11:02):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\mcutil.dll" and (not (module.path in ("c:\program files\McAfee Inc.\McAfee Total Protection 2009\*","c:\program files (x86)\McAfee Inc.\McAfee Total Protection 2009\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of mcutil.dll
id: 6572851b-5264-48a3-2775-5b9ff8452084
status: experimental
description: Detects possible DLL hijacking of mcutil.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/mcafee/mcutil.html
author: "Jai Minton - HuntressLabs"
date: 2024-08-07
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\mcutil.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\McAfee Inc.\McAfee Total Protection 2009\*'
            - 'c:\program files (x86)\McAfee Inc.\McAfee Total Protection 2009\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
