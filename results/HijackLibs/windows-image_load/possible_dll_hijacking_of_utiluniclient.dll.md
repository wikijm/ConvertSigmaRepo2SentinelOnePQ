```sql
// Translated content (automatically translated on 02-08-2025 01:52:58):
event.type="ModuleLoad" and (endpoint.os="windows" and module.path contains "\utiluniclient.dll")
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of utiluniclient.dll
id: 8929171b-5805-48a3-6769-5b9ff8388944
status: experimental
description: Detects possible DLL hijacking of utiluniclient.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/trendmicro/utiluniclient.html
author: "Wietze Beukema"
date: 2021-02-28
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\utiluniclient.dll'

    condition: selection 
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
