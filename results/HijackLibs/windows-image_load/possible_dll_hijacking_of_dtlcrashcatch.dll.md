```sql
// Translated content (automatically translated on 09-09-2026 03:40:34):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\dtlcrashcatch.dll" and (not (module.path contains "c:\\program files\\dtlsoft\\drivethelife\\" or module.path contains "c:\\program files (x86)\\dtlsoft\\drivethelife\\"))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of dtlcrashcatch.dll
id: 1846861b-8154-48a3-4104-5b9ff8331317
status: experimental
description: Detects possible DLL hijacking of dtlcrashcatch.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/ostoto/dtlcrashcatch.html
author: "Wietze Beukema"
date: 2026-06-14
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\dtlcrashcatch.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\dtlsoft\drivethelife\\*'
            - 'c:\program files (x86)\dtlsoft\drivethelife\\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
