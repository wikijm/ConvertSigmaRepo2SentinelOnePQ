```sql
// Translated content (automatically translated on 26-04-2025 10:11:02):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\dbgmodel.dll" and (not (module.path in ("c:\windows\system32\*","c:\windows\syswow64\*","c:\program files\Windows Kits\10\Debuggers\*\*","c:\program files (x86)\Windows Kits\10\Debuggers\*\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of dbgmodel.dll
id: 1149381b-2811-48a3-1599-5b9ff8991076
status: experimental
description: Detects possible DLL hijacking of dbgmodel.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/dbgmodel.html
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
        ImageLoaded: '*\dbgmodel.dll'
    filter:
        ImageLoaded:
            - 'c:\windows\system32\*'
            - 'c:\windows\syswow64\*'
            - 'c:\program files\Windows Kits\10\Debuggers\*\*'
            - 'c:\program files (x86)\Windows Kits\10\Debuggers\*\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
