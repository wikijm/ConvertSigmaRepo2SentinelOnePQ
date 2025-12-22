```sql
// Translated content (automatically translated on 22-12-2025 01:56:59):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\chrome_frame_helper.dll" and (not (module.path in ("c:\\users\*\\appdata\\local\\Google\\Chrome\\Application\*","c:\\program files\\Google\\Chrome\\Application\*","c:\\program files (x86)\\Google\\Chrome\\Application\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of chrome_frame_helper.dll
id: 9361151b-6722-48a3-2305-5b9ff8772021
status: experimental
description: Detects possible DLL hijacking of chrome_frame_helper.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/google/chrome_frame_helper.html
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
        ImageLoaded: '*\chrome_frame_helper.dll'
    filter:
        ImageLoaded:
            - 'c:\users\*\appdata\local\Google\Chrome\Application\*'
            - 'c:\program files\Google\Chrome\Application\*'
            - 'c:\program files (x86)\Google\Chrome\Application\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
