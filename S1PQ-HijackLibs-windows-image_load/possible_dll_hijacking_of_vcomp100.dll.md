```sql
// Translated content (automatically translated on 26-04-2025 10:11:02):
event.type="ModuleLoad" and (endpoint.os="windows" and module.path contains "\vcomp100.dll")
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of vcomp100.dll
id: 8078551b-1386-48a3-5209-5b9ff8188274
status: experimental
description: Detects possible DLL hijacking of vcomp100.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/adobe/vcomp100.html
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
        ImageLoaded: '*\vcomp100.dll'

    condition: selection 
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
