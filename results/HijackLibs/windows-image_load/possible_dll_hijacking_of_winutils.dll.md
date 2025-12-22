```sql
// Translated content (automatically translated on 22-12-2025 01:56:59):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\winutils.dll" and (not (module.path in ("c:\\program files\\Palo Alto Networks\\Traps\*","c:\\program files (x86)\\Palo Alto Networks\\Traps\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of winutils.dll
id: 8665401b-4150-48a3-8413-5b9ff8744995
status: experimental
description: Detects possible DLL hijacking of winutils.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/paloalto/winutils.html
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
        ImageLoaded: '*\winutils.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Palo Alto Networks\Traps\*'
            - 'c:\program files (x86)\Palo Alto Networks\Traps\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
