```sql
// Translated content (automatically translated on 22-12-2025 01:56:59):
event.type="Module Load" and (endpoint.os="windows" and module.path contains "\\tsvipsrv.dll")
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of tsvipsrv.dll
id: 9320321b-3647-48a3-1087-5b9ff8824480
status: experimental
description: Detects possible DLL hijacking of tsvipsrv.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/tsvipsrv.html
author: "Swachchhanda Shrawan Poudel"
date: 2025-09-05
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\tsvipsrv.dll'

    condition: selection 
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
