```sql
// Translated content (automatically translated on 08-09-2026 03:35:44):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\tak_deco_lib.dll" and (not (module.path contains "c:\\program files\\Mp3tag\\" or module.path contains "c:\\program files (x86)\\Mp3tag\\"))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of tak_deco_lib.dll
id: 8658271b-3513-48a3-4540-5b9ff8653630
status: experimental
description: Detects possible DLL hijacking of tak_deco_lib.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/mp3tag/tak_deco_lib.html
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
        ImageLoaded: '*\tak_deco_lib.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Mp3tag\\*'
            - 'c:\program files (x86)\Mp3tag\\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
