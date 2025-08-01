```sql
// Translated content (automatically translated on 02-08-2025 01:23:14):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\rcdll.dll" and (not (module.path contains "C:\Program Files (x86)\Microsoft Visual Studio\" or module.path contains "C:\Program Files (x86)\Windows Kits\"))))
```


# Original Sigma Rule:
```yaml
title: Potential Rcdll.DLL Sideloading
id: 6e78b74f-c762-4800-82ad-f66787f10c8a
status: test
description: Detects potential DLL sideloading of rcdll.dll
references:
    - https://www.trendmicro.com/en_us/research/23/c/iron-tiger-sysupdate-adds-linux-targeting.html
author: X__Junior (Nextron Systems)
date: 2023-03-13
modified: 2023-03-15
tags:
    - attack.defense-evasion
    - attack.privilege-escalation
    - attack.t1574.001
logsource:
    category: image_load
    product: windows
detection:
    selection:
        ImageLoaded|endswith: '\rcdll.dll'
    filter:
        ImageLoaded|startswith:
            - 'C:\Program Files (x86)\Microsoft Visual Studio\'
            - 'C:\Program Files (x86)\Windows Kits\'
    condition: selection and not filter
falsepositives:
    - Unknown
level: high
```
