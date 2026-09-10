```sql
// Translated content (automatically translated on 10-09-2026 03:38:18):
event.type="Module Load" and (endpoint.os="windows" and module.path contains "\\utils.dll")
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of utils.dll
id: 2729531b-4564-48a3-7410-5b9ff8258876
status: experimental
description: Detects possible DLL hijacking of utils.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/comodo/utils.html
author: "Austin Worline"
date: 2026-06-15
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\utils.dll'

    condition: selection 
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
