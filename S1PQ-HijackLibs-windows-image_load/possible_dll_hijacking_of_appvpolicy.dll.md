```sql
// Translated content (automatically translated on 26-04-2025 10:11:02):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\appvpolicy.dll" and (not (module.path in ("c:\windows\system32\*","c:\program files\Common Files\Microsoft Shared\ClickToRun\*","c:\program files (x86)\Common Files\Microsoft Shared\ClickToRun\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of appvpolicy.dll
id: 5334351b-2028-48a3-1241-5b9ff8107382
status: experimental
description: Detects possible DLL hijacking of appvpolicy.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/appvpolicy.html
author: "Chris Spehn"
date: 2021-08-16
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\appvpolicy.dll'
    filter:
        ImageLoaded:
            - 'c:\windows\system32\*'
            - 'c:\program files\Common Files\Microsoft Shared\ClickToRun\*'
            - 'c:\program files (x86)\Common Files\Microsoft Shared\ClickToRun\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
