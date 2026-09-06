```sql
// Translated content (automatically translated on 06-09-2026 03:30:39):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\scansts.dll" and (not (module.path="c:\\program files\\Quick Heal\\Quick Heal *\\*" or module.path="c:\\program files (x86)\\Quick Heal\\Quick Heal *\\*"))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of scansts.dll
id: 7777591b-3513-48a3-4540-5b9ff8870402
status: experimental
description: Detects possible DLL hijacking of scansts.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/quickheal/scansts.html
author: "Wietze Beukema"
date: 2026-09-01
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\scansts.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Quick Heal\Quick Heal *\\*'
            - 'c:\program files (x86)\Quick Heal\Quick Heal *\\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
