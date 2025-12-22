```sql
// Translated content (automatically translated on 22-12-2025 01:56:59):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\tbb.dll" and (not (module.path="c:\\program files\\Adobe\\Adobe Photoshop CC *\*" or module.path="c:\\program files (x86)\\Adobe\\Adobe Photoshop CC *\*"))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of tbb.dll
id: 3106521b-4746-48a3-1019-5b9ff8256030
status: experimental
description: Detects possible DLL hijacking of tbb.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/intel/tbb.html
author: "Jai Minton"
date: 2025-06-24
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\tbb.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Adobe\Adobe Photoshop CC *\*'
            - 'c:\program files (x86)\Adobe\Adobe Photoshop CC *\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
