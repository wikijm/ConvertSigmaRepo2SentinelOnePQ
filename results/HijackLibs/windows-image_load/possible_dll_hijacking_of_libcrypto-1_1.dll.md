```sql
// Translated content (automatically translated on 07-09-2026 03:30:29):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\libcrypto-1_1.dll" and (not (module.path contains "c:\\program files\\AOMEI Partition Assistant\\" or module.path contains "c:\\program files (x86)\\AOMEI Partition Assistant\\"))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of libcrypto-1_1.dll
id: 9426191b-5092-48a3-3345-5b9ff8221281
status: experimental
description: Detects possible DLL hijacking of libcrypto-1_1.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/aomei/libcrypto-1_1.html
author: "Harry Godridge - HuntressLabs"
date: 2026-08-09
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\libcrypto-1_1.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\AOMEI Partition Assistant\\*'
            - 'c:\program files (x86)\AOMEI Partition Assistant\\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
