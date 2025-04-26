```sql
// Translated content (automatically translated on 26-04-2025 10:11:02):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\dismcore.dll" and (not (module.path in ("c:\windows\system32\dism\*","c:\windows\syswow64\dism\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of dismcore.dll
id: 6725211b-5805-48a3-6769-5b9ff8788742
status: experimental
description: Detects possible DLL hijacking of dismcore.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/dismcore.html
author: "Wietze Beukema"
date: 2021-02-28
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\dismcore.dll'
    filter:
        ImageLoaded:
            - 'c:\windows\system32\dism\*'
            - 'c:\windows\syswow64\dism\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
