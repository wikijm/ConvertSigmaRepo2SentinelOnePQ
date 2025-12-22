```sql
// Translated content (automatically translated on 22-12-2025 01:26:06):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\outllib.dll" and (not (module.path contains "C:\\Program Files\\Microsoft Office\\OFFICE" or module.path contains "C:\\Program Files (x86)\\Microsoft Office\\OFFICE" or module.path contains "C:\\Program Files\\Microsoft Office\\Root\\OFFICE" or module.path contains "C:\\Program Files (x86)\\Microsoft Office\\Root\\OFFICE"))))
```


# Original Sigma Rule:
```yaml
title: Microsoft Office DLL Sideload
id: 829a3bdf-34da-4051-9cf4-8ed221a8ae4f
status: test
description: Detects DLL sideloading of DLLs that are part of Microsoft Office from non standard location
references:
    - https://hijacklibs.net/ # For list of DLLs that could be sideloaded (search for dlls mentioned here in there)
author: Nasreddine Bencherchali (Nextron Systems), Wietze Beukema (project and research)
date: 2022-08-17
modified: 2023-03-15
tags:
    - attack.defense-evasion
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1574.001
logsource:
    category: image_load
    product: windows
detection:
    selection:
        ImageLoaded|endswith: '\outllib.dll'
    filter:
        ImageLoaded|startswith:
            - 'C:\Program Files\Microsoft Office\OFFICE'
            - 'C:\Program Files (x86)\Microsoft Office\OFFICE'
            - 'C:\Program Files\Microsoft Office\Root\OFFICE'
            - 'C:\Program Files (x86)\Microsoft Office\Root\OFFICE'
    condition: selection and not filter
falsepositives:
    - Unlikely
level: high
```
