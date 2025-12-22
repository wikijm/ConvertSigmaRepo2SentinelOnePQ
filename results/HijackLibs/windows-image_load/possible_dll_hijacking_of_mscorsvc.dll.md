```sql
// Translated content (automatically translated on 22-12-2025 01:56:59):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\mscorsvc.dll" and (not (module.path="c:\\windows\\Microsoft.NET\\Framework\\v*\*" or module.path="c:\\windows\\Microsoft.NET\\Framework64\\v*\*"))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of mscorsvc.dll
id: 4602001b-4150-48a3-8413-5b9ff8132122
status: experimental
description: Detects possible DLL hijacking of mscorsvc.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/mscorsvc.html
author: "Wietze Beukema"
date: 2023-04-04
tags:
    - attack.defense_evasion
    - attack.T1574.001
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\mscorsvc.dll'
    filter:
        ImageLoaded:
            - 'c:\windows\Microsoft.NET\Framework\v*\*'
            - 'c:\windows\Microsoft.NET\Framework64\v*\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
