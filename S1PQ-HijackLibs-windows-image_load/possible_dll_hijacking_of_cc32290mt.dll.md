```sql
// Translated content (automatically translated on 26-04-2025 10:11:02):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\cc32290mt.dll" and (not (module.path in ("c:\program files\Ahnenblatt4\Ahnenblatt4.exe\*","c:\program files (x86)\Ahnenblatt4\Ahnenblatt4.exe\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of cc32290mt.dll
id: 8854761b-9003-48a3-1016-5b9ff8749285
status: experimental
description: Detects possible DLL hijacking of cc32290mt.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/ahnenblatt/cc32290mt.html
author: "Josh Allman"
date: 2025-02-25
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\cc32290mt.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Ahnenblatt4\Ahnenblatt4.exe\*'
            - 'c:\program files (x86)\Ahnenblatt4\Ahnenblatt4.exe\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
