```sql
// Translated content (automatically translated on 22-12-2025 01:26:06):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\iviewers.dll" and (not (module.path contains "C:\\Program Files (x86)\\Windows Kits\\" or module.path contains "C:\\Program Files\\Windows Kits\\"))))
```


# Original Sigma Rule:
```yaml
title: Potential Iviewers.DLL Sideloading
id: 4c21b805-4dd7-469f-b47d-7383a8fcb437
status: test
description: Detects potential DLL sideloading of "iviewers.dll" (OLE/COM Object Interface Viewer)
references:
    - https://www.secureworks.com/research/shadowpad-malware-analysis
author: X__Junior (Nextron Systems)
date: 2023-03-21
tags:
    - attack.persistence
    - attack.defense-evasion
    - attack.privilege-escalation
    - attack.t1574.001
logsource:
    category: image_load
    product: windows
detection:
    selection:
        ImageLoaded|endswith: '\iviewers.dll'
    filter:
        ImageLoaded|startswith:
            - 'C:\Program Files (x86)\Windows Kits\'
            - 'C:\Program Files\Windows Kits\'
    condition: selection and not filter
falsepositives:
    - Unknown
level: high
```
