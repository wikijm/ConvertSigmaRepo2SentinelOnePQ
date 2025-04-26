```sql
// Translated content (automatically translated on 26-04-2025 10:11:02):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\iepdf32.dll" and (not (module.path in ("c:\program files\Handy Viewer\*","c:\program files (x86)\Handy Viewer\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of iepdf32.dll
id: 1171071b-1386-48a3-5209-5b9ff8410482
status: experimental
description: Detects possible DLL hijacking of iepdf32.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/handysoftware/iepdf32.html
author: "Jai Minton - HuntressLabs"
date: 2024-07-09
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\iepdf32.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Handy Viewer\*'
            - 'c:\program files (x86)\Handy Viewer\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
