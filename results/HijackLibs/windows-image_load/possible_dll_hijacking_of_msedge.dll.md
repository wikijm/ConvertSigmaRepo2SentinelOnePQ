```sql
// Translated content (automatically translated on 22-10-2025 01:44:32):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\msedge.dll" and (not (module.path in ("c:\\program files\\Microsoft\\Edge\\Application\*\*","c:\\program files (x86)\\Microsoft\\Edge\\Application\*\*","c:\\program files\\Microsoft\\Edgewebview\\Application\*\*","c:\\program files (x86)\\Microsoft\\Edgewebview\\Application\*\*","c:\\program files\\Microsoft\\EdgeCore\*\*","c:\\program files (x86)\\Microsoft\\EdgeCore\*\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of msedge.dll
id: 8987611b-6939-48a3-6071-5b9ff8509508
status: experimental
description: Detects possible DLL hijacking of msedge.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/msedge.html
author: "Swachchhanda Shrawan Poudel"
date: 2024-07-25
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\msedge.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Microsoft\Edge\Application\*\*'
            - 'c:\program files (x86)\Microsoft\Edge\Application\*\*'
            - 'c:\program files\Microsoft\Edgewebview\Application\*\*'
            - 'c:\program files (x86)\Microsoft\Edgewebview\Application\*\*'
            - 'c:\program files\Microsoft\EdgeCore\*\*'
            - 'c:\program files (x86)\Microsoft\EdgeCore\*\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
