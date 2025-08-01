```sql
// Translated content (automatically translated on 02-08-2025 01:52:58):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\ci.dll" and (not (module.path in ("c:\program files\Digiarty\WinX Blu-ray Decrypter\*","c:\program files (x86)\Digiarty\WinX Blu-ray Decrypter\*","c:\windows\system32\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of ci.dll
id: 3188551b-6171-48a3-7472-5b9ff8356391
status: experimental
description: Detects possible DLL hijacking of ci.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/digiarty/ci.html
author: "Jai Minton - HuntressLabs"
date: 2024-05-06
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\ci.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Digiarty\WinX Blu-ray Decrypter\*'
            - 'c:\program files (x86)\Digiarty\WinX Blu-ray Decrypter\*'
            - 'c:\windows\system32\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
