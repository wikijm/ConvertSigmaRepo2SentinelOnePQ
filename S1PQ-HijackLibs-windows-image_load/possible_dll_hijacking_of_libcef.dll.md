```sql
// Translated content (automatically translated on 26-04-2025 10:11:02):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\libcef.dll" and (not (module.path in ("c:\program files\NVIDIA Corporation\NVIDIA GeForce Experience\*","c:\program files (x86)\NVIDIA Corporation\NVIDIA GeForce Experience\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of libcef.dll
id: 6527071b-7750-48a3-4174-5b9ff8584870
status: experimental
description: Detects possible DLL hijacking of libcef.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/nvidia/libcef.html
author: "Matt Anderson - HuntressLabs"
date: 2024-04-13
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\libcef.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\NVIDIA Corporation\NVIDIA GeForce Experience\*'
            - 'c:\program files (x86)\NVIDIA Corporation\NVIDIA GeForce Experience\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
