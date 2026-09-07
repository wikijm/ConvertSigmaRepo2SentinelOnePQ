```sql
// Translated content (automatically translated on 07-09-2026 03:30:29):
event.type="Module Load" and (endpoint.os="windows" and module.path contains "\\vsdbg.dll")
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of vsdbg.dll
id: 4601661b-8730-48a3-1369-5b9ff8653643
status: experimental
description: Detects possible DLL hijacking of vsdbg.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/external/vsdbg.html
author: "Kostas"
date: 2026-08-13
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\vsdbg.dll'

    condition: selection 
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
