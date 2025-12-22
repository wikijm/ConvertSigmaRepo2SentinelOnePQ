```sql
// Translated content (automatically translated on 22-12-2025 01:26:06):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\mscorsvc.dll" and (not (module.path contains "C:\\Windows\\Microsoft.NET\\Framework\\" or module.path contains "C:\\Windows\\Microsoft.NET\\Framework64\\" or module.path contains "C:\\Windows\\Microsoft.NET\\FrameworkArm\\" or module.path contains "C:\\Windows\\Microsoft.NET\\FrameworkArm64\\" or module.path contains "C:\\Windows\\WinSxS\\"))))
```


# Original Sigma Rule:
```yaml
title: Potential DLL Sideloading Of MsCorSvc.DLL
id: cdb15e19-c2d0-432a-928e-e49c8c60dcf2
status: test
description: Detects potential DLL sideloading of "mscorsvc.dll".
references:
    - https://hijacklibs.net/entries/microsoft/built-in/mscorsvc.html
author: Wietze Beukema
date: 2024-07-11
modified: 2025-02-26
tags:
    - attack.privilege-escalation
    - attack.persistence
    - attack.defense-evasion
    - attack.t1574.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded|endswith: '\mscorsvc.dll'
    filter_main_generic:
        ImageLoaded|startswith:
            - 'C:\Windows\Microsoft.NET\Framework\'
            - 'C:\Windows\Microsoft.NET\Framework64\'
            - 'C:\Windows\Microsoft.NET\FrameworkArm\'
            - 'C:\Windows\Microsoft.NET\FrameworkArm64\'
            - 'C:\Windows\WinSxS\'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Legitimate applications loading their own versions of the DLL mentioned in this rule.
level: medium
```
