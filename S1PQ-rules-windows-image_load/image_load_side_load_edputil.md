```sql
// Translated content (automatically translated on 02-08-2025 01:23:14):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\edputil.dll" and (not (module.path contains "C:\Windows\System32\" or module.path contains "C:\Windows\SysWOW64\" or module.path contains "C\Windows\WinSxS\"))))
```


# Original Sigma Rule:
```yaml
title: Potential Edputil.DLL Sideloading
id: e4903324-1a10-4ed3-981b-f6fe3be3a2c2
status: test
description: Detects potential DLL sideloading of "edputil.dll"
references:
    - https://alternativeto.net/news/2023/5/cybercriminals-use-wordpad-vulnerability-to-spread-qbot-malware/
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
        ImageLoaded|endswith: '\edputil.dll'
    filter_main_generic:
        ImageLoaded|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Windows\SysWOW64\'
            - 'C\Windows\WinSxS\'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unlikely
level: high
```
