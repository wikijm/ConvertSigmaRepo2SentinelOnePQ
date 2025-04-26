```sql
// Translated content (automatically translated on 26-04-2025 10:11:02):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\uxcore.dll" and (not (module.path in ("c:\program files\windows live\installer\*","c:\program files (x86)\windows live\installer\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of uxcore.dll
id: 1416641b-5077-48a3-3793-5b9ff8228927
status: experimental
description: Detects possible DLL hijacking of uxcore.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/external/uxcore.html
author: "Jai Minton - HuntressLabs"
date: 2025-01-22
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\uxcore.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\windows live\installer\*'
            - 'c:\program files (x86)\windows live\installer\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
