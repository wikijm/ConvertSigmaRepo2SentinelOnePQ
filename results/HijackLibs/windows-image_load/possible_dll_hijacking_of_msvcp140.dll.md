```sql
// Translated content (automatically translated on 02-09-2025 01:41:16):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\msvcp140.dll" and (not (module.path in ("c:\\windows\\system32\*","c:\\windows\\syswow64\*","c:\\program files\*","c:\\program files (x86)\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of msvcp140.dll
id: 3432361b-3119-48a3-1242-5b9ff8554273
status: experimental
description: Detects possible DLL hijacking of msvcp140.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/msvcp140.html
author: "Swachchhanda Shrawan Poudel"
date: 2025-07-12
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\msvcp140.dll'
    filter:
        ImageLoaded:
            - 'c:\windows\system32\*'
            - 'c:\windows\syswow64\*'
            - 'c:\program files\*'
            - 'c:\program files (x86)\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
