```sql
// Translated content (automatically translated on 26-04-2025 10:11:02):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\libglib-2.0-0.dll" and (not (module.path in ("c:\program files\Wireshark\*","c:\program files (x86)\Wireshark\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of libglib-2.0-0.dll
id: 4660921b-9569-48a3-1936-5b9ff8639303
status: experimental
description: Detects possible DLL hijacking of libglib-2.0-0.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/wireshark/libglib-2.0-0.html
author: "Jai Minton - HuntressLabs"
date: 2024-04-15
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\libglib-2.0-0.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Wireshark\*'
            - 'c:\program files (x86)\Wireshark\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
