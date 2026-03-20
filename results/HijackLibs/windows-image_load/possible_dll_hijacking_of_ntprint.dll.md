```sql
// Translated content (automatically translated on 20-03-2026 02:23:41):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\ntprint.dll" and (not (module.path contains "c:\\windows\\system32\\" or module.path contains "c:\\windows\\syswow64\\"))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of ntprint.dll
id: 1969621b-7194-48a3-1387-5b9ff8446202
status: experimental
description: Detects possible DLL hijacking of ntprint.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/ntprint.html
author: "SanSan"
date: 2026-03-06
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\ntprint.dll'
    filter:
        ImageLoaded:
            - 'c:\windows\system32\\*'
            - 'c:\windows\syswow64\\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
