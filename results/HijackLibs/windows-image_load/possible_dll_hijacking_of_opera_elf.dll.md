```sql
// Translated content (automatically translated on 22-12-2025 01:56:59):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\opera_elf.dll" and (not (module.path in ("c:\\users\*\\appdata\\local\\Programs\\Opera\*\*","c:\\users\*\\appdata\\local\\Programs\\Opera GX\*\*","c:\\program files\\Opera\*\*","c:\\program files (x86)\\Opera\*\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of opera_elf.dll
id: 3451111b-5254-48a3-5583-5b9ff8715208
status: experimental
description: Detects possible DLL hijacking of opera_elf.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/opera/opera_elf.html
author: "Wietze Beukema"
date: 2023-07-28
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\opera_elf.dll'
    filter:
        ImageLoaded:
            - 'c:\users\*\appdata\local\Programs\Opera\*\*'
            - 'c:\users\*\appdata\local\Programs\Opera GX\*\*'
            - 'c:\program files\Opera\*\*'
            - 'c:\program files (x86)\Opera\*\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
