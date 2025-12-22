```sql
// Translated content (automatically translated on 22-12-2025 01:56:59):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\lockdown.dll" and (not (module.path in ("c:\\program files\\McAfee\\VirusScan Enterprise\*","c:\\program files (x86)\\McAfee\\VirusScan Enterprise\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of lockdown.dll
id: 2232211b-1318-48a3-1317-5b9ff8905604
status: experimental
description: Detects possible DLL hijacking of lockdown.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/mcafee/lockdown.html
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
        ImageLoaded: '*\lockdown.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\McAfee\VirusScan Enterprise\*'
            - 'c:\program files (x86)\McAfee\VirusScan Enterprise\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
