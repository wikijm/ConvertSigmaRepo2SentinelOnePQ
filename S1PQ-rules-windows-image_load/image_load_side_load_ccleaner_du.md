```sql
// Translated content (automatically translated on 22-12-2025 01:26:06):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\CCleanerDU.dll" and (not ((src.process.image.path contains "C:\\Program Files\\CCleaner\\" or src.process.image.path contains "C:\\Program Files (x86)\\CCleaner\\") and (src.process.image.path contains "\\CCleaner.exe" or src.process.image.path contains "\\CCleaner64.exe")))))
```


# Original Sigma Rule:
```yaml
title: Potential CCleanerDU.DLL Sideloading
id: 1fbc0671-5596-4e17-8682-f020a0b995dc
status: test
description: Detects potential DLL sideloading of "CCleanerDU.dll"
references:
    - https://lab52.io/blog/2344-2/
author: X__Junior (Nextron Systems)
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
        ImageLoaded|endswith: '\CCleanerDU.dll'
    filter_main_path:
        Image|startswith:
            - 'C:\Program Files\CCleaner\'
            - 'C:\Program Files (x86)\CCleaner\'
        Image|endswith:
            - '\CCleaner.exe'
            - '\CCleaner64.exe'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - False positives could occur from other custom installation paths. Apply additional filters accordingly.
level: medium
```
