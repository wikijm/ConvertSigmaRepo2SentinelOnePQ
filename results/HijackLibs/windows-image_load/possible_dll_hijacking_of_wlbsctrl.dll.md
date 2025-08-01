```sql
// Translated content (automatically translated on 02-08-2025 01:52:58):
event.type="ModuleLoad" and (endpoint.os="windows" and module.path contains "\wlbsctrl.dll")
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of wlbsctrl.dll
id: 7274671b-4908-48a3-8140-5b9ff8212003
status: experimental
description: Detects possible DLL hijacking of wlbsctrl.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/wlbsctrl.html
author: "Wietze Beukema"
date: 2022-06-12
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\wlbsctrl.dll'

    condition: selection 
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
