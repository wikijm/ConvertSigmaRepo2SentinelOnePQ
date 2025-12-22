```sql
// Translated content (automatically translated on 22-12-2025 01:56:59):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\tmdbg64.dll" and (not (module.path in ("c:\\users\*\\appdata\\local\\Temp\\ClnExtor\\PCCNT\*","c:\\program files\\Trend Micro\\Security Agent\*","c:\\program files (x86)\\Trend Micro\\Security Agent\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of tmdbg64.dll
id: 9722621b-9632-48a3-5733-5b9ff8437989
status: experimental
description: Detects possible DLL hijacking of tmdbg64.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/trendmicro/tmdbg64.html
author: "Still Hsu"
date: 2025-11-05
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\tmdbg64.dll'
    filter:
        ImageLoaded:
            - 'c:\users\*\appdata\local\Temp\ClnExtor\PCCNT\*'
            - 'c:\program files\Trend Micro\Security Agent\*'
            - 'c:\program files (x86)\Trend Micro\Security Agent\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
