```sql
// Translated content (automatically translated on 22-12-2025 01:56:59):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\mspgimme.dll" and (not (module.path in ("c:\\program files\\Common Files\\Microsoft Shared\\MODI\\11.0\*","c:\\program files (x86)\\Common Files\\Microsoft Shared\\MODI\\11.0\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of mspgimme.dll
id: 4129981b-9291-48a3-5273-5b9ff8568681
status: experimental
description: Detects possible DLL hijacking of mspgimme.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/external/mspgimme.html
author: "Josh Allman"
date: 2025-03-27
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\mspgimme.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Common Files\Microsoft Shared\MODI\11.0\*'
            - 'c:\program files (x86)\Common Files\Microsoft Shared\MODI\11.0\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
