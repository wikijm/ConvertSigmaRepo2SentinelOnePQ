```sql
// Translated content (automatically translated on 22-12-2025 01:56:59):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\sentinelagentcore.dll" and (not (module.path="c:\\program files\\SentinelOne\\Sentinel Agent *\*" or module.path="c:\\program files (x86)\\SentinelOne\\Sentinel Agent *\*"))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of sentinelagentcore.dll
id: 6609691b-5226-48a3-9110-5b9ff8127832
status: experimental
description: Detects possible DLL hijacking of sentinelagentcore.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/sentinelone/sentinelagentcore.html
author: "Amelia Casley"
date: 2025-08-13
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\sentinelagentcore.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\SentinelOne\Sentinel Agent *\*'
            - 'c:\program files (x86)\SentinelOne\Sentinel Agent *\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
