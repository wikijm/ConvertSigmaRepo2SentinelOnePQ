```sql
// Translated content (automatically translated on 01-03-2026 02:34:34):
event.type="Module Load" and (endpoint.os="windows" and module.path contains "\\dsp_bridge_x64.dll")
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of dsp_bridge_x64.dll
id: 3179261b-3028-48a3-8802-5b9ff8680997
status: experimental
description: Detects possible DLL hijacking of dsp_bridge_x64.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/kugou/dsp_bridge_x64.html
author: "Zhangir Ospanov"
date: 2026-01-06
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\dsp_bridge_x64.dll'

    condition: selection 
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
