```sql
// Translated content (automatically translated on 22-12-2025 01:26:06):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\CCleanerReactivator.dll" and (not ((src.process.image.path contains "C:\\Program Files\\CCleaner\\" or src.process.image.path contains "C:\\Program Files (x86)\\CCleaner\\") and src.process.image.path contains "\\CCleanerReactivator.exe"))))
```


# Original Sigma Rule:
```yaml
title: Potential CCleanerReactivator.DLL Sideloading
id: 3735d5ac-d770-4da0-99ff-156b180bc600
status: test
description: Detects potential DLL sideloading of "CCleanerReactivator.dll"
references:
    - https://lab52.io/blog/2344-2/
author: X__Junior
date: 2023-07-13
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
        ImageLoaded|endswith: '\CCleanerReactivator.dll'
    filter_main_path:
        Image|startswith:
            - 'C:\Program Files\CCleaner\'
            - 'C:\Program Files (x86)\CCleaner\'
        Image|endswith: '\CCleanerReactivator.exe'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - False positives could occur from other custom installation paths. Apply additional filters accordingly.
level: medium
```
