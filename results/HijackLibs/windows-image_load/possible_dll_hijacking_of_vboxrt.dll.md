```sql
// Translated content (automatically translated on 22-12-2025 01:56:59):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\vboxrt.dll" and (not (module.path in ("c:\\program files\\Oracle\\VirtualBox\*","c:\\program files (x86)\\Oracle\\VirtualBox\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of vboxrt.dll
id: 4315841b-9569-48a3-1936-5b9ff8731884
status: experimental
description: Detects possible DLL hijacking of vboxrt.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/oracle/vboxrt.html
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
        ImageLoaded: '*\vboxrt.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Oracle\VirtualBox\*'
            - 'c:\program files (x86)\Oracle\VirtualBox\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
