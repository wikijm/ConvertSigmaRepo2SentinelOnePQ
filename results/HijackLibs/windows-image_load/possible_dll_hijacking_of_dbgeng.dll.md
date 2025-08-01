```sql
// Translated content (automatically translated on 02-08-2025 01:52:58):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\dbgeng.dll" and (not (module.path in ("c:\program files\Windows Kits\*\Debuggers\x86\*","c:\program files (x86)\Windows Kits\*\Debuggers\x86\*","c:\program files\Windows Kits\*\Debuggers\x64\*","c:\program files (x86)\Windows Kits\*\Debuggers\x64\*","c:\program files\Windows Kits\*\Debuggers\arm\*","c:\program files (x86)\Windows Kits\*\Debuggers\arm\*","c:\program files\Windows Kits\*\Debuggers\arm64\*","c:\program files (x86)\Windows Kits\*\Debuggers\arm64\*","c:\windows\system32\*","c:\windows\syswow64\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of dbgeng.dll
id: 9774421b-9223-48a3-6181-5b9ff8657582
status: experimental
description: Detects possible DLL hijacking of dbgeng.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/external/dbgeng.html
author: "Wietze Beukema"
date: 2023-03-01
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\dbgeng.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Windows Kits\*\Debuggers\x86\*'
            - 'c:\program files (x86)\Windows Kits\*\Debuggers\x86\*'
            - 'c:\program files\Windows Kits\*\Debuggers\x64\*'
            - 'c:\program files (x86)\Windows Kits\*\Debuggers\x64\*'
            - 'c:\program files\Windows Kits\*\Debuggers\arm\*'
            - 'c:\program files (x86)\Windows Kits\*\Debuggers\arm\*'
            - 'c:\program files\Windows Kits\*\Debuggers\arm64\*'
            - 'c:\program files (x86)\Windows Kits\*\Debuggers\arm64\*'
            - 'c:\windows\system32\*'
            - 'c:\windows\syswow64\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
