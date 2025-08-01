```sql
// Translated content (automatically translated on 02-08-2025 01:23:14):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\dbgmodel.dll" and (not (module.path contains "C:\Windows\System32\" or module.path contains "C:\Windows\SysWOW64\" or module.path contains "C:\Windows\WinSxS\")) and (not (module.path contains "C:\Program Files\WindowsApps\Microsoft.WinDbg_" or (module.path contains "C:\Program Files (x86)\Windows Kits\" or module.path contains "C:\Program Files\Windows Kits\")))))
```


# Original Sigma Rule:
```yaml
title: Potential DLL Sideloading Of DbgModel.DLL
id: fef394cd-f44d-4040-9b18-95d92fe278c0
status: test
description: Detects potential DLL sideloading of "DbgModel.dll"
references:
    - https://hijacklibs.net/entries/microsoft/built-in/dbgmodel.html
author: Gary Lobermier
date: 2024-07-11
modified: 2024-07-22
tags:
    - attack.defense-evasion
    - attack.t1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded|endswith: '\dbgmodel.dll'
    filter_main_generic:
        ImageLoaded|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Windows\SysWOW64\'
            - 'C:\Windows\WinSxS\'
    filter_optional_windbg:
        ImageLoaded|startswith: 'C:\Program Files\WindowsApps\Microsoft.WinDbg_'
    filter_optional_windows_kits:
        ImageLoaded|startswith:
            - 'C:\Program Files (x86)\Windows Kits\'
            - 'C:\Program Files\Windows Kits\'
    condition: selection and not 1 of filter_main_* and not 1 of filter_optional_*
falsepositives:
    - Legitimate applications loading their own versions of the DLL mentioned in this rule
level: medium
```
