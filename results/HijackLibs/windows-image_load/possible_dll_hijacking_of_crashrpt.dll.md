```sql
// Translated content (automatically translated on 01-03-2026 02:34:34):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\crashrpt.dll" and (not (module.path contains "c:\\program files\\MPC-HC\\CrashReporter\\" or module.path contains "c:\\program files (x86)\\MPC-HC\\CrashReporter\\"))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of crashrpt.dll
id: 9651331b-1257-48a3-6224-5b9ff8973528
status: experimental
description: Detects possible DLL hijacking of crashrpt.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/idol/crashrpt.html
author: "Still Hsu"
date: 2026-01-09
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\crashrpt.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\MPC-HC\CrashReporter\\*'
            - 'c:\program files (x86)\MPC-HC\CrashReporter\\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
