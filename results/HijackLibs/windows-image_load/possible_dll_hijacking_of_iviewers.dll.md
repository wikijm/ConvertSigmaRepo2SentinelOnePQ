```sql
// Translated content (automatically translated on 02-08-2025 01:52:58):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\iviewers.dll" and (not (module.path in ("c:\program files\Windows Kits\10\bin\*\x86\*","c:\program files (x86)\Windows Kits\10\bin\*\x86\*","c:\program files\Windows Kits\10\bin\*\x64\*","c:\program files (x86)\Windows Kits\10\bin\*\x64\*","c:\program files\Windows Kits\10\bin\*\arm\*","c:\program files (x86)\Windows Kits\10\bin\*\arm\*","c:\program files\Windows Kits\10\bin\*\arm64\*","c:\program files (x86)\Windows Kits\10\bin\*\arm64\*")))))
```


# Original Sigma Rule:
```yaml
title: Possible DLL Hijacking of iviewers.dll
id: 1295571b-6727-48a3-6557-5b9ff8430907
status: experimental
description: Detects possible DLL hijacking of iviewers.dll by looking for suspicious image loads, loading this DLL from unexpected locations.
references:
    - https://hijacklibs.net/entries/microsoft/external/iviewers.html
author: "Wietze Beukema"
date: 2022-06-14
tags:
    - attack.defense_evasion
    - attack.T1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded: '*\iviewers.dll'
    filter:
        ImageLoaded:
            - 'c:\program files\Windows Kits\10\bin\*\x86\*'
            - 'c:\program files (x86)\Windows Kits\10\bin\*\x86\*'
            - 'c:\program files\Windows Kits\10\bin\*\x64\*'
            - 'c:\program files (x86)\Windows Kits\10\bin\*\x64\*'
            - 'c:\program files\Windows Kits\10\bin\*\arm\*'
            - 'c:\program files (x86)\Windows Kits\10\bin\*\arm\*'
            - 'c:\program files\Windows Kits\10\bin\*\arm64\*'
            - 'c:\program files (x86)\Windows Kits\10\bin\*\arm64\*'

    condition: selection and not filter
falsepositives:
    - False positives are likely. This rule is more suitable for hunting than for generating detections.

```
