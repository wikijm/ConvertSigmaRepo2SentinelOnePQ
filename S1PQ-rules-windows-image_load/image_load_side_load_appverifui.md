```sql
// Translated content (automatically translated on 02-08-2025 01:23:14):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\appverifUI.dll" and (not ((src.process.image.path in ("C:\Windows\SysWOW64\appverif.exe","C:\Windows\System32\appverif.exe")) and (module.path contains "C:\Windows\System32\" or module.path contains "C:\Windows\SysWOW64\" or module.path contains "C:\Windows\WinSxS\")))))
```


# Original Sigma Rule:
```yaml
title: Potential appverifUI.DLL Sideloading
id: ee6cea48-c5b6-4304-a332-10fc6446f484
status: test
description: Detects potential DLL sideloading of "appverifUI.dll"
references:
    - https://web.archive.org/web/20220519091349/https://fatrodzianko.com/2020/02/15/dll-side-loading-appverif-exe/
author: X__Junior (Nextron Systems)
date: 2023-06-20
tags:
    - attack.defense-evasion
    - attack.privilege-escalation
    - attack.t1574.001
logsource:
    category: image_load
    product: windows
detection:
    selection:
        ImageLoaded|endswith: '\appverifUI.dll'
    filter_main_legit_path:
        Image:
            - 'C:\Windows\SysWOW64\appverif.exe'
            - 'C:\Windows\System32\appverif.exe'
        ImageLoaded|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Windows\SysWOW64\'
            - 'C:\Windows\WinSxS\'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unlikely
level: high
```
