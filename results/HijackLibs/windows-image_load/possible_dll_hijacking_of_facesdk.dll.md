```sql
// Translated content (automatically translated on 02-08-2025 01:52:58):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\facesdk.dll" and (not (module.path in ("c:\program files\luxand\facesdk\bin\win64\*","c:\program files (x86)\luxand\facesdk\bin\win64\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of facesdk.dll
id: 4818681b-4150-48a3-8413-5b9ff8954421
status: experimental
description: Detects possible DLL hijacking of facesdk.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/luxand/facesdk.html
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
        ImageLoaded: '*\facesdk.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\luxand\facesdk\bin\win64\*'
            - 'c:\program files (x86)\luxand\facesdk\bin\win64\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
