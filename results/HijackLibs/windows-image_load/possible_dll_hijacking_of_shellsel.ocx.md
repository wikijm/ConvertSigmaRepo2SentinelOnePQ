```sql
// Translated content (automatically translated on 02-08-2025 01:52:58):
event.type="ModuleLoad" and (endpoint.os="windows" and module.path contains "\shellsel.ocx")
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of shellsel.ocx
id: 2664661b-4150-48a3-8413-5b9ff8735128
status: experimental
description: Detects possible DLL hijacking of shellsel.ocx by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/symantec/shellsel.html
author: "Wietze Beukema"
date: 2023-04-04
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\shellsel.ocx'

    condition: selection 
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
