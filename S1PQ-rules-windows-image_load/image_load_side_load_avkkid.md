```sql
// Translated content (automatically translated on 22-12-2025 01:26:06):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\AVKkid.dll" and (not ((src.process.image.path contains "C:\\Program Files (x86)\\G DATA\\" or src.process.image.path contains "C:\\Program Files\\G DATA\\") and src.process.image.path contains "\\AVKKid.exe" and (module.path contains "C:\\Program Files (x86)\\G DATA\\" or module.path contains "C:\\Program Files\\G DATA\\")))))
```


# Original Sigma Rule:
```yaml
title: Potential AVKkid.DLL Sideloading
id: 952ed57c-8f99-453d-aee0-53a49c22f95d
status: test
description: Detects potential DLL sideloading of "AVKkid.dll"
references:
    - https://research.checkpoint.com/2023/beyond-the-horizon-traveling-the-world-on-camaro-dragons-usb-flash-drives/
author: X__Junior (Nextron Systems)
date: 2023-08-03
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
        ImageLoaded|endswith: '\AVKkid.dll'
    filter_main_legit_path:
        Image|contains:
            - 'C:\Program Files (x86)\G DATA\'
            - 'C:\Program Files\G DATA\'
        Image|endswith: '\AVKKid.exe'
        ImageLoaded|startswith:
            - 'C:\Program Files (x86)\G DATA\'
            - 'C:\Program Files\G DATA\'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: medium
```
