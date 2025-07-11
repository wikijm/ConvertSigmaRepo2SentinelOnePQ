```sql
// Translated content (automatically translated on 11-07-2025 01:23:23):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\dbgcore.dll" and (not (module.path contains "C:\Program Files (x86)\" or module.path contains "C:\Program Files\" or module.path contains "C:\Windows\SoftwareDistribution\" or module.path contains "C:\Windows\System32\" or module.path contains "C:\Windows\SystemTemp\" or module.path contains "C:\Windows\SysWOW64\" or module.path contains "C:\Windows\WinSxS\")) and (not module.path contains "\Steam\bin\cef\cef.win7x64\dbgcore.dll")))
```


# Original Sigma Rule:
```yaml
title: Potential DLL Sideloading Of DBGCORE.DLL
id: 9ca2bf31-0570-44d8-a543-534c47c33ed7
status: test
description: Detects DLL sideloading of "dbgcore.dll"
references:
    - https://hijacklibs.net/ # For list of DLLs that could be sideloaded (search for dlls mentioned here in there)
author: Nasreddine Bencherchali (Nextron Systems), Wietze Beukema (project and research)
date: 2022-10-25
modified: 2023-05-05
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
        ImageLoaded|endswith: '\dbgcore.dll'
    filter_main_generic:
        ImageLoaded|startswith:
            - 'C:\Program Files (x86)\'
            - 'C:\Program Files\'
            - 'C:\Windows\SoftwareDistribution\'
            - 'C:\Windows\System32\'
            - 'C:\Windows\SystemTemp\'
            - 'C:\Windows\SysWOW64\'
            - 'C:\Windows\WinSxS\'
    filter_optional_steam:
        ImageLoaded|endswith: '\Steam\bin\cef\cef.win7x64\dbgcore.dll'
    condition: selection and not 1 of filter_main_* and not 1 of filter_optional_*
falsepositives:
    - Legitimate applications loading their own versions of the DLL mentioned in this rule
level: medium
```
