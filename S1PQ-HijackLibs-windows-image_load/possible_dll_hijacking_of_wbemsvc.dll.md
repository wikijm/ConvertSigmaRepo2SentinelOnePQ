```sql
// Translated content (automatically translated on 26-04-2025 10:11:02):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\wbemsvc.dll" and (not (module.path in ("c:\windows\system32\wbem\*","c:\windows\syswow64\wbem\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of wbemsvc.dll
id: 6612901b-2897-48a3-6541-5b9ff8659258
status: experimental
description: Detects possible DLL hijacking of wbemsvc.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/wbemsvc.html
author: "Wietze Beukema"
date: 2022-05-21
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\wbemsvc.dll'
    filter:
        ImageLoaded:
            - 'c:\windows\system32\wbem\*'
            - 'c:\windows\syswow64\wbem\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
