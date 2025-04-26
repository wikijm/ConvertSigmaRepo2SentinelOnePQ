```sql
// Translated content (automatically translated on 26-04-2025 10:11:02):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\vender.dll" and (not (module.path in ("c:\program files\ASUS\GPU TweakII\*","c:\program files (x86)\ASUS\GPU TweakII\*","c:\program files\ASUS\VGA COM\*\*","c:\program files (x86)\ASUS\VGA COM\*\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of vender.dll
id: 9481841b-4150-48a3-8413-5b9ff8267972
status: experimental
description: Detects possible DLL hijacking of vender.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/asus/vender.html
author: "Wietze Beukema"
date: 2023-04-04
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\vender.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\ASUS\GPU TweakII\*'
            - 'c:\program files (x86)\ASUS\GPU TweakII\*'
            - 'c:\program files\ASUS\VGA COM\*\*'
            - 'c:\program files (x86)\ASUS\VGA COM\*\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
