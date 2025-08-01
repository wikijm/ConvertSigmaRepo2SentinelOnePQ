```sql
// Translated content (automatically translated on 02-08-2025 01:52:58):
event.type="ModuleLoad" and (endpoint.os="windows" and module.path contains "\mstracer.dll")
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of mstracer.dll
id: 2382211b-6722-48a3-2305-5b9ff8323341
status: experimental
description: Detects possible DLL hijacking of mstracer.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/mstracer.html
author: "Wietze Beukema"
date: 2021-12-08
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\mstracer.dll'

    condition: selection 
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
