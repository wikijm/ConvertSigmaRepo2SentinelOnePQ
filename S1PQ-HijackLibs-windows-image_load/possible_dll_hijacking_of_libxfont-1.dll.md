```sql
// Translated content (automatically translated on 26-04-2025 10:11:02):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\libxfont-1.dll" and (not (module.path in ("c:\program files\Mobatek\MobaXterm Personal Edition\*","c:\program files (x86)\Mobatek\MobaXterm Personal Edition\*","c:\program files\Mobatek\MobaXterm\*","c:\program files (x86)\Mobatek\MobaXterm\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of libxfont-1.dll
id: 4954711b-9809-48a3-9172-5b9ff8180439
status: experimental
description: Detects possible DLL hijacking of libxfont-1.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/mobatek/libxfont-1.html
author: "Jai Minton - HuntressLabs"
date: 2024-05-10
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\libxfont-1.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Mobatek\MobaXterm Personal Edition\*'
            - 'c:\program files (x86)\Mobatek\MobaXterm Personal Edition\*'
            - 'c:\program files\Mobatek\MobaXterm\*'
            - 'c:\program files (x86)\Mobatek\MobaXterm\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
