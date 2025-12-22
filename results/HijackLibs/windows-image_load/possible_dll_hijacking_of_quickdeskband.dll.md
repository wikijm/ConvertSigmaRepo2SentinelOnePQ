```sql
// Translated content (automatically translated on 22-12-2025 01:56:59):
event.type="Module Load" and (endpoint.os="windows" and module.path contains "\\quickdeskband.dll")
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of quickdeskband.dll
id: 8061491b-6843-48a3-5852-5b9ff8483736
status: experimental
description: Detects possible DLL hijacking of quickdeskband.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/lenovo/quickdeskband.html
author: "Wietze Beukema"
date: 2024-07-15
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\quickdeskband.dll'

    condition: selection 
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
