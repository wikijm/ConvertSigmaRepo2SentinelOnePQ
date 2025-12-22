```sql
// Translated content (automatically translated on 22-12-2025 01:56:59):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\krpt.dll" and (not (module.path in ("c:\\program files\\Kingsoft\\WPS Office\*\\office6\*","c:\\program files (x86)\\Kingsoft\\WPS Office\*\\office6\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of krpt.dll
id: 4415741b-9766-48a3-4354-5b9ff8616475
status: experimental
description: Detects possible DLL hijacking of krpt.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/kingsoft/krpt.html
author: "Still Hsu"
date: 2024-11-09
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\krpt.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Kingsoft\WPS Office\*\office6\*'
            - 'c:\program files (x86)\Kingsoft\WPS Office\*\office6\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
