```sql
// Translated content (automatically translated on 26-04-2025 10:11:02):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\skinutils.dll" and (not (module.path in ("c:\program files\ICQLite\*","c:\program files (x86)\ICQLite\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of skinutils.dll
id: 1801631b-6171-48a3-7472-5b9ff8387108
status: experimental
description: Detects possible DLL hijacking of skinutils.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/icq/skinutils.html
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
        ImageLoaded: '*\skinutils.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\ICQLite\*'
            - 'c:\program files (x86)\ICQLite\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
