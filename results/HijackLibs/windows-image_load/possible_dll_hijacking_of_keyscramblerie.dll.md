```sql
// Translated content (automatically translated on 02-08-2025 01:52:58):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\keyscramblerie.dll" and (not (module.path in ("c:\program files\KeyScrambler\*","c:\program files (x86)\KeyScrambler\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of keyscramblerie.dll
id: 3315771b-9569-48a3-1936-5b9ff8463838
status: experimental
description: Detects possible DLL hijacking of keyscramblerie.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/qfx/keyscramblerie.html
author: "Matt Anderson - HuntressLabs, Swachchhanda Shrawan Poudel"
date: 2024-04-15
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\keyscramblerie.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\KeyScrambler\*'
            - 'c:\program files (x86)\KeyScrambler\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
