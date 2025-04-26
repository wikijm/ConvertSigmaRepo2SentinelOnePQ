```sql
// Translated content (automatically translated on 26-04-2025 10:11:02):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\rcdll.dll" and (not (module.path in ("c:\program files\Windows Kits\10\bin\*\*\*","c:\program files (x86)\Windows Kits\10\bin\*\*\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of rcdll.dll
id: 1324851b-2811-48a3-1599-5b9ff8815748
status: experimental
description: Detects possible DLL hijacking of rcdll.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/external/rcdll.html
author: "Gary Lobermier"
date: 2023-05-22
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\rcdll.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Windows Kits\10\bin\*\*\*'
            - 'c:\program files (x86)\Windows Kits\10\bin\*\*\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
