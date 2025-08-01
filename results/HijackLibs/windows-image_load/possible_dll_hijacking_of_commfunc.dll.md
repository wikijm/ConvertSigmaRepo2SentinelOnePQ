```sql
// Translated content (automatically translated on 02-08-2025 01:52:58):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\commfunc.dll" and (not (module.path in ("c:\program files\Lenovo\Communications Utility\*","c:\program files (x86)\Lenovo\Communications Utility\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of commfunc.dll
id: 9530031b-6722-48a3-2305-5b9ff8893283
status: experimental
description: Detects possible DLL hijacking of commfunc.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/lenovo/commfunc.html
author: "Wietze Beukema"
date: 2021-12-08
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\commfunc.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Lenovo\Communications Utility\*'
            - 'c:\program files (x86)\Lenovo\Communications Utility\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
