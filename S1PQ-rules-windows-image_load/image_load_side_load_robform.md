```sql
// Translated content (automatically translated on 22-12-2025 01:26:06):
event.type="Module Load" and (endpoint.os="windows" and ((module.path contains "\\roboform.dll" or module.path contains "\\roboform-x64.dll") and (not ((src.process.image.path contains " C:\\Program Files (x86)\\Siber Systems\\AI RoboForm\\" or src.process.image.path contains " C:\\Program Files\\Siber Systems\\AI RoboForm\\") and (src.process.image.path contains "\\robotaskbaricon.exe" or src.process.image.path contains "\\robotaskbaricon-x64.exe")))))
```


# Original Sigma Rule:
```yaml
title: Potential RoboForm.DLL Sideloading
id: f64c9b2d-b0ad-481d-9d03-7fc75020892a
status: test
description: Detects potential DLL sideloading of "roboform.dll", a DLL used by RoboForm Password Manager
references:
    - https://twitter.com/StopMalvertisin/status/1648604148848549888
    - https://twitter.com/t3ft3lb/status/1656194831830401024
    - https://www.roboform.com/
author: X__Junior (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
date: 2023-05-14
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
        ImageLoaded|endswith:
            - '\roboform.dll'
            - '\roboform-x64.dll'
    filter_main_path:
        Image|startswith:
            - ' C:\Program Files (x86)\Siber Systems\AI RoboForm\'
            - ' C:\Program Files\Siber Systems\AI RoboForm\'
        Image|endswith:
            - '\robotaskbaricon.exe'
            - '\robotaskbaricon-x64.exe'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - If installed on a per-user level, the path would be located in "AppData\Local". Add additional filters to reflect this mode of installation
level: medium
```
