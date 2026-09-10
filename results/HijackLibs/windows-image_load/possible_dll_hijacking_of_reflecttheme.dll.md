```sql
// Translated content (automatically translated on 10-09-2026 03:38:18):
event.type="Module Load" and (endpoint.os="windows" and module.path contains "\\reflecttheme.dll")
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of reflecttheme.dll
id: 6255481b-6911-48a3-5228-5b9ff8567031
status: experimental
description: Detects possible DLL hijacking of reflecttheme.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/macrium/reflecttheme.html
author: "Austin Worline"
date: 2026-08-11
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\reflecttheme.dll'

    condition: selection 
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
