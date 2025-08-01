```sql
// Translated content (automatically translated on 02-08-2025 01:23:14):
event.type="ModuleLoad" and (endpoint.os="windows" and ((module.path contains "\RjvPlatform.dll" and src.process.image.path="\SystemResetPlatform.exe") and (not src.process.image.path contains "C:\Windows\System32\SystemResetPlatform\")))
```


# Original Sigma Rule:
```yaml
title: Potential RjvPlatform.DLL Sideloading From Non-Default Location
id: 0e0bc253-07ed-43f1-816d-e1b220fe8971
status: test
description: Detects potential DLL sideloading of "RjvPlatform.dll" by "SystemResetPlatform.exe" located in a non-default location.
references:
    - https://twitter.com/0gtweet/status/1666716511988330499
author: X__Junior (Nextron Systems)
date: 2023-06-09
tags:
    - attack.defense-evasion
    - attack.privilege-escalation
    - attack.t1574.001
logsource:
    category: image_load
    product: windows
detection:
    selection:
        ImageLoaded|endswith: '\RjvPlatform.dll'
        Image: '\SystemResetPlatform.exe'
    filter_main_legit_path:
        Image|startswith: 'C:\Windows\System32\SystemResetPlatform\'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unlikely
level: high
```
