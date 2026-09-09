```sql
// Translated content (automatically translated on 09-09-2026 03:40:34):
event.type="Module Load" and (endpoint.os="windows" and module.path contains "\\mingwm10.dll")
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of mingwm10.dll
id: 3658201b-3513-48a3-4540-5b9ff8927087
status: experimental
description: Detects possible DLL hijacking of mingwm10.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/mingw/mingwm10.html
author: "Wietze Beukema"
date: 2026-09-01
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\mingwm10.dll'

    condition: selection 
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
