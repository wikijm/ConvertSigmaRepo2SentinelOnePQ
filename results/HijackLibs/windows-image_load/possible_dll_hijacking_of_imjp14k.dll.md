```sql
// Translated content (automatically translated on 22-12-2025 01:56:59):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\imjp14k.dll" and (not (module.path in ("c:\\windows\\system32\*","c:\\windows\\syswow64\*","c:\\program files\\Common Files\\Microsoft Shared\\IME14\\SHARED\*","c:\\program files (x86)\\Common Files\\Microsoft Shared\\IME14\\SHARED\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of imjp14k.dll
id: 1912701b-7371-48a3-5678-5b9ff8552736
status: experimental
description: Detects possible DLL hijacking of imjp14k.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/external/imjp14k.html
author: "Wietze Beukema"
date: 2024-09-08
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\imjp14k.dll'
    filter:
        ImageLoaded:
            - 'c:\windows\system32\*'
            - 'c:\windows\syswow64\*'
            - 'c:\program files\Common Files\Microsoft Shared\IME14\SHARED\*'
            - 'c:\program files (x86)\Common Files\Microsoft Shared\IME14\SHARED\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
