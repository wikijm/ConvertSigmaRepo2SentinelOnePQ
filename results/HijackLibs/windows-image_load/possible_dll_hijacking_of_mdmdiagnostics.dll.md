```sql
// Translated content (automatically translated on 19-10-2025 01:49:40):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\mdmdiagnostics.dll" and (not module.path="c:\\windows\\system32\*")))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of mdmdiagnostics.dll
id: 4508101b-9395-48a3-4833-5b9ff8964655
status: experimental
description: Detects possible DLL hijacking of mdmdiagnostics.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/mdmdiagnostics.html
author: "Wietze Beukema"
date: 2021-02-27
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\mdmdiagnostics.dll'
    filter:
        ImageLoaded:
            - 'c:\windows\system32\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
