```sql
// Translated content (automatically translated on 09-09-2026 03:40:34):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\datastate.dll" and (not module.path contains "C:\\Program Files (x86)\\IObit\\AdvancedSystemCare\\")))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of datastate.dll
id: 4672431b-1502-48a3-7254-5b9ff8799765
status: experimental
description: Detects possible DLL hijacking of datastate.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/iobit/datastate.html
author: "Cristian Poenaru - HuntressLabs"
date: 2026-08-10
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\datastate.dll'
    filter:
        ImageLoaded:
            - 'C:\Program Files (x86)\IObit\AdvancedSystemCare\\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
