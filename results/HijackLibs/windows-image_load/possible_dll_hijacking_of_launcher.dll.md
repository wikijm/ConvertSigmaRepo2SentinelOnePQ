```sql
// Translated content (automatically translated on 11-06-2025 01:48:33):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\launcher.dll" and (not (module.path in ("c:\program files\SQL Developer\ide\bin\*","c:\program files (x86)\SQL Developer\ide\bin\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of launcher.dll
id: 1948171b-6085-48a3-6339-5b9ff8262762
status: experimental
description: Detects possible DLL hijacking of launcher.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/oracle/launcher.html
author: "Jai Minton"
date: 2025-05-07
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\launcher.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\SQL Developer\ide\bin\*'
            - 'c:\program files (x86)\SQL Developer\ide\bin\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
