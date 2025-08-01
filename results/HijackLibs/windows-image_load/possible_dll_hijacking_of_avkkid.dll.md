```sql
// Translated content (automatically translated on 02-08-2025 01:52:58):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\avkkid.dll" and (not (module.path in ("c:\program files\G DATA\TotalSecurity\avkkid\*","c:\program files (x86)\G DATA\TotalSecurity\avkkid\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of avkkid.dll
id: 2869201b-8907-48a3-9464-5b9ff8599279
status: experimental
description: Detects possible DLL hijacking of avkkid.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/gdata/avkkid.html
author: "Wietze Beukema"
date: 2025-02-15
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\avkkid.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\G DATA\TotalSecurity\avkkid\*'
            - 'c:\program files (x86)\G DATA\TotalSecurity\avkkid\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
