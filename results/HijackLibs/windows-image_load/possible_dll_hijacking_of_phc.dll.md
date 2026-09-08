```sql
// Translated content (automatically translated on 08-09-2026 03:35:44):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\phc.dll" and (not module.path="c:\\users\\*\\appdata\\roaming\\Foxit Software\\Classic\\Addon\\Foxit PDF Editor\\plugins\\*")))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of phc.dll
id: 5119041b-1310-48a3-7290-5b9ff8194985
status: experimental
description: Detects possible DLL hijacking of phc.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/foxit/phc.html
author: "Still Hsu"
date: 2026-07-21
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\phc.dll'
    filter:
        ImageLoaded:
            - 'c:\users\\*\appdata\roaming\Foxit Software\Classic\Addon\Foxit PDF Editor\plugins\\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
