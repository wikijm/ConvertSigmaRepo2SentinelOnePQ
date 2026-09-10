```sql
// Translated content (automatically translated on 10-09-2026 03:38:18):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\cdlmso.dll" and (not (module.path contains "c:\\program files\\Microsoft Office\\Office14\\" or module.path contains "c:\\program files (x86)\\Microsoft Office\\Office14\\"))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of cdlmso.dll
id: 8613931b-8442-48a3-5283-5b9ff8887785
status: experimental
description: Detects possible DLL hijacking of cdlmso.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/external/cdlmso.html
author: "Adam Mooney - HuntressLabs"
date: 2026-07-14
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\cdlmso.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Microsoft Office\Office14\\*'
            - 'c:\program files (x86)\Microsoft Office\Office14\\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
