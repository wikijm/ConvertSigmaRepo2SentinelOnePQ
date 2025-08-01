```sql
// Translated content (automatically translated on 02-08-2025 01:52:58):
event.type="ModuleLoad" and (endpoint.os="windows" and module.path contains "\relay.dll")
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of relay.dll
id: 4509561b-2773-48a3-5383-5b9ff8502377
status: experimental
description: Detects possible DLL hijacking of relay.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/canon/relay.html
author: "Jai Minton - HuntressLabs"
date: 2024-05-27
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\relay.dll'

    condition: selection 
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
