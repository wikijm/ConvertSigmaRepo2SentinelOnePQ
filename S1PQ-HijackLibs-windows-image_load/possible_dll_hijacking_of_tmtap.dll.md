```sql
// Translated content (automatically translated on 26-04-2025 10:11:02):
event.type="ModuleLoad" and (endpoint.os="windows" and module.path contains "\tmtap.dll")
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of tmtap.dll
id: 8739701b-2945-48a3-7988-5b9ff8844509
status: experimental
description: Detects possible DLL hijacking of tmtap.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/trendmicro/tmtap.html
author: "Wietze Beukema"
date: 2022-05-26
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\tmtap.dll'

    condition: selection 
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
