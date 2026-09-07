```sql
// Translated content (automatically translated on 07-09-2026 03:30:29):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\microsoft.windowsappruntime.bootstrap.dll" and (not (module.path contains "c:\\windows\\system32\\" or module.path contains "c:\\program files\\" or module.path contains "c:\\program files (x86)\\"))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of microsoft.windowsappruntime.bootstrap.dll
id: 9661121b-5855-48a3-4834-5b9ff8192045
status: experimental
description: Detects possible DLL hijacking of microsoft.windowsappruntime.bootstrap.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/external/microsoft.windowsappruntime.bootstrap.html
author: "Swachchhanda Shrawan Poudel"
date: 2026-04-23
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\microsoft.windowsappruntime.bootstrap.dll'
    filter:
        ImageLoaded:
            - 'c:\windows\system32\\*'
            - 'c:\program files\\*'
            - 'c:\program files (x86)\\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
