```sql
// Translated content (automatically translated on 07-09-2026 03:30:29):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\wblindp2.dll" and (not (module.path contains "c:\\program files\\Stardock\\WindowBlinds\\" or module.path contains "c:\\program files (x86)\\Stardock\\WindowBlinds\\"))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of wblindp2.dll
id: 3394061b-4996-48a3-6789-5b9ff8174260
status: experimental
description: Detects possible DLL hijacking of wblindp2.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/stardock/wblindp2.html
author: "Harry Godridge - HuntressLabs"
date: 2026-07-30
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\wblindp2.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Stardock\WindowBlinds\\*'
            - 'c:\program files (x86)\Stardock\WindowBlinds\\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
