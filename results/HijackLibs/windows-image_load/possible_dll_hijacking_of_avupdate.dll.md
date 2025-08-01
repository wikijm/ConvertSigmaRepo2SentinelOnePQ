```sql
// Translated content (automatically translated on 02-08-2025 01:52:58):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\avupdate.dll" and (not (module.path in ("c:\program files\Confer\scanner\upd.exe\*","c:\program files (x86)\Confer\scanner\upd.exe\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of avupdate.dll
id: 8597761b-7136-48a3-7154-5b9ff8168353
status: experimental
description: Detects possible DLL hijacking of avupdate.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/carbonblack/avupdate.html
author: "Josh Allman"
date: 2025-02-18
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\avupdate.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Confer\scanner\upd.exe\*'
            - 'c:\program files (x86)\Confer\scanner\upd.exe\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
