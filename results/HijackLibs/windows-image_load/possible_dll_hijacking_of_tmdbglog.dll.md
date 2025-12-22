```sql
// Translated content (automatically translated on 22-12-2025 01:56:59):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\tmdbglog.dll" and (not (module.path in ("c:\\program files\\Trend Micro\\Titanium\*","c:\\program files (x86)\\Trend Micro\\Titanium\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of tmdbglog.dll
id: 1956941b-5201-48a3-9406-5b9ff8905624
status: experimental
description: Detects possible DLL hijacking of tmdbglog.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/trendmicro/tmdbglog.html
author: "Christiaan Beek"
date: 2023-01-16
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\tmdbglog.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Trend Micro\Titanium\*'
            - 'c:\program files (x86)\Trend Micro\Titanium\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
