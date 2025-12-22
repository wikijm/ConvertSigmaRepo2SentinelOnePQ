```sql
// Translated content (automatically translated on 22-12-2025 01:56:59):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\dal_keepalives.dll" and (not (module.path in ("c:\\program files\\audinate\\shared files\*","c:\\program files (x86)\\audinate\\shared files\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of dal_keepalives.dll
id: 3880461b-8907-48a3-9464-5b9ff8429562
status: experimental
description: Detects possible DLL hijacking of dal_keepalives.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/audinate/dal_keepalives.html
author: "Wietze Beukema"
date: 2025-02-15
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\dal_keepalives.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\audinate\shared files\*'
            - 'c:\program files (x86)\audinate\shared files\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
