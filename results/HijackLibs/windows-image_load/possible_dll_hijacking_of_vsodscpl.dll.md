```sql
// Translated content (automatically translated on 02-08-2025 01:52:58):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\vsodscpl.dll" and (not (module.path in ("c:\program files\McAfee\VirusScan Enterprise\*","c:\program files (x86)\McAfee\VirusScan Enterprise\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of vsodscpl.dll
id: 8664221b-1318-48a3-1317-5b9ff8845464
status: experimental
description: Detects possible DLL hijacking of vsodscpl.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/mcafee/vsodscpl.html
author: "Wietze Beukema"
date: 2022-06-13
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\vsodscpl.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\McAfee\VirusScan Enterprise\*'
            - 'c:\program files (x86)\McAfee\VirusScan Enterprise\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
