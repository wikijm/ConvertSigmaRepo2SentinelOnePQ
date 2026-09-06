```sql
// Translated content (automatically translated on 06-09-2026 03:30:39):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\hpbprndiloc.dll" and (not (module.path="c:\\program files\\Hewlett-Packard\\*\\*" or module.path="c:\\program files (x86)\\Hewlett-Packard\\*\\*"))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of hpbprndiloc.dll
id: 9654501b-7866-48a3-6831-5b9ff8138138
status: experimental
description: Detects possible DLL hijacking of hpbprndiloc.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/hp/hpbprndiloc.html
author: "Swachchhanda Shrawan Poudel"
date: 2026-05-15
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\hpbprndiloc.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Hewlett-Packard\\*\\*'
            - 'c:\program files (x86)\Hewlett-Packard\\*\\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
