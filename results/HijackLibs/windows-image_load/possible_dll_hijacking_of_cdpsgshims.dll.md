```sql
// Translated content (automatically translated on 02-08-2025 01:52:58):
event.type="ModuleLoad" and (endpoint.os="windows" and module.path contains "\cdpsgshims.dll")
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of cdpsgshims.dll
id: 4611701b-9122-48a3-7130-5b9ff8297414
status: experimental
description: Detects possible DLL hijacking of cdpsgshims.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/cdpsgshims.html
author: "k4nfr3"
date: 2022-08-15
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\cdpsgshims.dll'

    condition: selection 
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
