```sql
// Translated content (automatically translated on 22-12-2025 01:26:06):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\EACore.dll" and (not ((src.process.image.path contains "C:\\Program Files\\Electronic Arts\\EA Desktop\\" and src.process.image.path contains "\\EACoreServer.exe") and module.path contains "C:\\Program Files\\Electronic Arts\\EA Desktop\\"))))
```


# Original Sigma Rule:
```yaml
title: Potential EACore.DLL Sideloading
id: edd3ddc3-386f-4ba5-9ada-4376b2cfa7b5
status: test
description: Detects potential DLL sideloading of "EACore.dll"
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
        ImageLoaded|endswith: '\EACore.dll'
    filter_main_legit_path:
        Image|contains|all:
            - 'C:\Program Files\Electronic Arts\EA Desktop\'
            - '\EACoreServer.exe'
        ImageLoaded|startswith: 'C:\Program Files\Electronic Arts\EA Desktop\'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unlikely
level: high
```
