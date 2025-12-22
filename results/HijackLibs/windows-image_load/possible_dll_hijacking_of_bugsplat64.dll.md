```sql
// Translated content (automatically translated on 22-12-2025 01:56:59):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\bugsplat64.dll" and (not (module.path contains "c:\\program files\\Nitro\\PDF Pro\\" or module.path contains "c:\\program files (x86)\\Nitro\\PDF Pro\\" or module.path="c:\\program files\\Nitro\\Pro\*" or module.path="c:\\program files (x86)\\Nitro\\Pro\*"))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of bugsplat64.dll
id: 9968901b-1823-48a3-3698-5b9ff8332489
status: experimental
description: Detects possible DLL hijacking of bugsplat64.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/3rd_party/bugsplat/bugsplat64.html
author: "Swachchhanda Shrawan Poudel"
date: 2025-02-27
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\bugsplat64.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Nitro\PDF Pro\\*'
            - 'c:\program files (x86)\Nitro\PDF Pro\\*'
            - 'c:\program files\Nitro\Pro\*'
            - 'c:\program files (x86)\Nitro\Pro\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
