```sql
// Translated content (automatically translated on 22-12-2025 01:56:59):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\mediainfo_i386.dll" and (not (module.path in ("c:\\program files\\MediaInfo\*","c:\\program files (x86)\\MediaInfo\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of mediainfo_i386.dll
id: 1377101b-4736-48a3-5188-5b9ff8695284
status: experimental
description: Detects possible DLL hijacking of mediainfo_i386.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/mediainfo/mediainfo_i386.html
author: "Jai Minton - HuntressLabs"
date: 2024-06-13
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\mediainfo_i386.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\MediaInfo\*'
            - 'c:\program files (x86)\MediaInfo\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
