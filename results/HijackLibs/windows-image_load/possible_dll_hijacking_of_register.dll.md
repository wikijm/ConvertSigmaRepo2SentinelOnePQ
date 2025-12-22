```sql
// Translated content (automatically translated on 22-12-2025 01:56:59):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\register.dll" and (not (module.path in ("c:\\program files\\IObit\\Driver Booster\*\*","c:\\program files (x86)\\IObit\\Driver Booster\*\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of register.dll
id: 3815041b-6171-48a3-7472-5b9ff8863799
status: experimental
description: Detects possible DLL hijacking of register.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/iobit/register.html
author: "Jai Minton - HuntressLabs"
date: 2024-05-06
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\register.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\IObit\Driver Booster\*\*'
            - 'c:\program files (x86)\IObit\Driver Booster\*\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
