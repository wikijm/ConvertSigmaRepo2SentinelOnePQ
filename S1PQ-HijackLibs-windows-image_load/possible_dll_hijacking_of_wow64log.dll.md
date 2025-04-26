```sql
// Translated content (automatically translated on 26-04-2025 10:11:02):
event.type="ModuleLoad" and (endpoint.os="windows" and module.path contains "\wow64log.dll")
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of wow64log.dll
id: 1854581b-8475-48a3-5606-5b9ff8458296
status: experimental
description: Detects possible DLL hijacking of wow64log.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/wow64log.html
author: "ice-wzl"
date: 2025-01-01
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\wow64log.dll'

    condition: selection 
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
