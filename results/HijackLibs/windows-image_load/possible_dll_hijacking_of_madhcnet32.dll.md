```sql
// Translated content (automatically translated on 22-12-2025 01:56:59):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\madhcnet32.dll" and (not (module.path in ("c:\\program files\\Multimedia\\K-Lite Codec Pack\\Filters\\madVR\*","c:\\program files (x86)\\Multimedia\\K-Lite Codec Pack\\Filters\\madVR\*","c:\\program files\\K-Lite Codec Pack\\Filters\\madVR\*","c:\\program files (x86)\\K-Lite Codec Pack\\Filters\\madVR\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of madhcnet32.dll
id: 7923811b-4026-48a3-2477-5b9ff8629450
status: experimental
description: Detects possible DLL hijacking of madhcnet32.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/systemsoftwaremathiasrauen/madhcnet32.html
author: "Jai Minton - HuntressLabs"
date: 2025-04-10
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\madhcnet32.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Multimedia\K-Lite Codec Pack\Filters\madVR\*'
            - 'c:\program files (x86)\Multimedia\K-Lite Codec Pack\Filters\madVR\*'
            - 'c:\program files\K-Lite Codec Pack\Filters\madVR\*'
            - 'c:\program files (x86)\K-Lite Codec Pack\Filters\madVR\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
