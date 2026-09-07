```sql
// Translated content (automatically translated on 07-09-2026 03:30:29):
event.type="Module Load" and (endpoint.os="windows" and module.path contains "\\autorun.dll")
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of autorun.dll
id: 3025161b-8154-48a3-4104-5b9ff8818204
status: experimental
description: Detects possible DLL hijacking of autorun.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/external/autorun.html
author: "Wietze Beukema"
date: 2026-06-14
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\autorun.dll'

    condition: selection 
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
