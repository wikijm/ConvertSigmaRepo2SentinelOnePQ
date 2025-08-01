```sql
// Translated content (automatically translated on 02-08-2025 01:52:58):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\msedge_elf.dll" and (not (module.path in ("c:\program files\Microsoft\Edge\Application\*\*","c:\program files (x86)\Microsoft\Edge\Application\*\*","c:\program files\Microsoft\EdgeCore\*\*","c:\program files (x86)\Microsoft\EdgeCore\*\*","c:\program files\Microsoft\EdgeWebView\*\*","c:\program files (x86)\Microsoft\EdgeWebView\*\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of msedge_elf.dll
id: 3135231b-6795-48a3-8155-5b9ff8191152
status: experimental
description: Detects possible DLL hijacking of msedge_elf.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/built-in/msedge_elf.html
author: "Still Hsu"
date: 2024-07-10
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\msedge_elf.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Microsoft\Edge\Application\*\*'
            - 'c:\program files (x86)\Microsoft\Edge\Application\*\*'
            - 'c:\program files\Microsoft\EdgeCore\*\*'
            - 'c:\program files (x86)\Microsoft\EdgeCore\*\*'
            - 'c:\program files\Microsoft\EdgeWebView\*\*'
            - 'c:\program files (x86)\Microsoft\EdgeWebView\*\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
