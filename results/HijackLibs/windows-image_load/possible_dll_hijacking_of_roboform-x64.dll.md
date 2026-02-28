```sql
// Translated content (automatically translated on 28-02-2026 02:04:27):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\roboform-x64.dll" and (not (module.path="c:\\program files\\Siber Systems\\AI RoboForm\\*\\*" or module.path="c:\\program files (x86)\\Siber Systems\\AI RoboForm\\*\\*"))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of roboform-x64.dll
id: 2016811b-1497-48a3-1258-5b9ff8516792
status: experimental
description: Detects possible DLL hijacking of roboform-x64.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/sibersystems/roboform-x64.html
author: "Rick Gatenby"
date: 2026-02-03
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\roboform-x64.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Siber Systems\AI RoboForm\\*\\*'
            - 'c:\program files (x86)\Siber Systems\AI RoboForm\\*\\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
