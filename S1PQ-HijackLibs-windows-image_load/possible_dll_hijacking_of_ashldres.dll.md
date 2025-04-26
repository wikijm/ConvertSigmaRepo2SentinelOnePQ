```sql
// Translated content (automatically translated on 26-04-2025 10:11:02):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\ashldres.dll" and (not (module.path in ("c:\program files\McAfee.com\VSO\*","c:\program files (x86)\McAfee.com\VSO\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of ashldres.dll
id: 2697231b-6722-48a3-2305-5b9ff8580020
status: experimental
description: Detects possible DLL hijacking of ashldres.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/mcafee/ashldres.html
author: "Wietze Beukema"
date: 2021-12-08
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\ashldres.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\McAfee.com\VSO\*'
            - 'c:\program files (x86)\McAfee.com\VSO\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
