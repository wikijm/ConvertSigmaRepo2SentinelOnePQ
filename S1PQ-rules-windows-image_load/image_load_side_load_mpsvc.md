```sql
// Translated content (automatically translated on 20-03-2025 01:11:06):
event.type="ModuleLoad" and (endpoint.os="windows" and (module.path contains "\MpSvc.dll" and (not (module.path contains "C:\Program Files\Windows Defender\" or module.path contains "C:\ProgramData\Microsoft\Windows Defender\Platform\" or module.path contains "C:\Windows\WinSxS\"))))
```


# Original Sigma Rule:
```yaml
title: Potential DLL Sideloading Of MpSvc.DLL
id: 5ba243e5-8165-4cf7-8c69-e1d3669654c1
status: experimental
description: Detects potential DLL sideloading of "MpSvc.dll".
references:
    - https://hijacklibs.net/entries/microsoft/built-in/mpsvc.html
author: Nasreddine Bencherchali (Nextron Systems), Wietze Beukema
date: 2024-07-11
tags:
    - attack.defense-evasion
    - attack.t1574.002
logsource:
    product: windows
    category: image_load
detection:
    selection:
        ImageLoaded|endswith: '\MpSvc.dll'
    filter_main_generic:
        ImageLoaded|startswith:
            - 'C:\Program Files\Windows Defender\'
            - 'C:\ProgramData\Microsoft\Windows Defender\Platform\'
            - 'C:\Windows\WinSxS\'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Legitimate applications loading their own versions of the DLL mentioned in this rule.
level: medium
```
