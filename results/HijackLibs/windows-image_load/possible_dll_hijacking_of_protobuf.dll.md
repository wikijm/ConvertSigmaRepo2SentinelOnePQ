```sql
// Translated content (automatically translated on 08-09-2026 03:35:44):
event.type="Module Load" and (endpoint.os="windows" and module.path contains "\\protobuf.dll")
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of protobuf.dll
id: 5112681b-2169-48a3-8083-5b9ff8241524
status: experimental
description: Detects possible DLL hijacking of protobuf.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/irzyxa/protobuf.html
author: "Austin Worline"
date: 2026-04-14
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\protobuf.dll'

    condition: selection 
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
