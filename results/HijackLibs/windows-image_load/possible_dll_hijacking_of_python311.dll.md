```sql
// Translated content (automatically translated on 02-08-2025 01:52:58):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\python311.dll" and (not (module.path in ("c:\program files\Python311\*","c:\program files (x86)\Python311\*","c:\users\*\appdata\local\Programs\Python\Python311\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of python311.dll
id: 2990441b-2202-48a3-8342-5b9ff8695619
status: experimental
description: Detects possible DLL hijacking of python311.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/python/python311.html
author: "Swachchhanda Shrawan Poudel"
date: 2024-10-02
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\python311.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Python311\*'
            - 'c:\program files (x86)\Python311\*'
            - 'c:\users\*\appdata\local\Programs\Python\Python311\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
