```sql
// Translated content (automatically translated on 22-12-2025 01:56:59):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\corefoundation.dll" and (not (module.path in ("c:\\program files\\Common Files\\Apple\\Apple Application Support\*","c:\\program files (x86)\\Common Files\\Apple\\Apple Application Support\*","c:\\program files\\iTunes\*","c:\\program files (x86)\\iTunes\*","c:\\windows\\system32\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of corefoundation.dll
id: 2984081b-7750-48a3-4174-5b9ff8664569
status: experimental
description: Detects possible DLL hijacking of corefoundation.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/apple/corefoundation.html
author: "Matt Anderson - HuntressLabs"
date: 2024-04-13
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\corefoundation.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Common Files\Apple\Apple Application Support\*'
            - 'c:\program files (x86)\Common Files\Apple\Apple Application Support\*'
            - 'c:\program files\iTunes\*'
            - 'c:\program files (x86)\iTunes\*'
            - 'c:\windows\system32\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
