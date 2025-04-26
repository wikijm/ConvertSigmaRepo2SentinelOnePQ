```sql
// Translated content (automatically translated on 26-04-2025 10:11:02):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\smadhook32c.dll" and (not (module.path in ("c:\program files\Smadav\*","c:\program files (x86)\Smadav\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of smadhook32c.dll
id: 3416181b-4150-48a3-8413-5b9ff8316275
status: experimental
description: Detects possible DLL hijacking of smadhook32c.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/smadav/smadhook32c.html
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
        ImageLoaded: '*\smadhook32c.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Smadav\*'
            - 'c:\program files (x86)\Smadav\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
