```sql
// Translated content (automatically translated on 22-12-2025 01:56:59):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\nvsmartmax.dll" and (not (module.path in ("c:\\program files\\NVIDIA Corporation\\Display\*","c:\\program files (x86)\\NVIDIA Corporation\\Display\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of nvsmartmax.dll
id: 6820621b-3819-48a3-7381-5b9ff8297672
status: experimental
description: Detects possible DLL hijacking of nvsmartmax.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/nvidia/nvsmartmax.html
author: "Wietze Beukema"
date: 2023-09-04
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\nvsmartmax.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\NVIDIA Corporation\Display\*'
            - 'c:\program files (x86)\NVIDIA Corporation\Display\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
