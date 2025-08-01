```sql
// Translated content (automatically translated on 02-08-2025 01:52:58):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\cc3260mt.dll" and (not (module.path in ("c:\program files\TiVo\Desktop\*","c:\program files (x86)\TiVo\Desktop\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of cc3260mt.dll
id: 5945181b-3546-48a3-3513-5b9ff8463170
status: experimental
description: Detects possible DLL hijacking of cc3260mt.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/tivo/cc3260mt.html
author: "Jai Minton - HuntressLabs"
date: 2025-02-19
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\cc3260mt.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\TiVo\Desktop\*'
            - 'c:\program files (x86)\TiVo\Desktop\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
