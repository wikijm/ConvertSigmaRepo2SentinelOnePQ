```sql
// Translated content (automatically translated on 22-12-2025 01:56:59):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\asfbncor.dll" and (not (module.path in ("c:\\program files\\Replay Media Splitter\*","c:\\program files (x86)\\Replay Media Splitter\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of asfbncor.dll
id: 3362011b-9675-48a3-8026-5b9ff8248289
status: experimental
description: Detects possible DLL hijacking of asfbncor.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/radioactive/asfbncor.html
author: "Jai Minton"
date: 2025-05-06
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\asfbncor.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Replay Media Splitter\*'
            - 'c:\program files (x86)\Replay Media Splitter\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
