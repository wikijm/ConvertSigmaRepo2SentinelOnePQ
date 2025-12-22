```sql
// Translated content (automatically translated on 22-12-2025 01:56:59):
event.type="Module Load" and (endpoint.os="windows" and module.path contains "\\providers.dll")
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of providers.dll
id: 4710111b-5388-48a3-9769-5b9ff8810087
status: experimental
description: Detects possible DLL hijacking of providers.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/npm/providers.html
author: "Wietze Beukema"
date: 2022-08-01
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\providers.dll'

    condition: selection 
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
