```sql
// Translated content (automatically translated on 22-12-2025 01:26:06):
event.type="Module Load" and (endpoint.os="windows" and ((src.process.image.path="C:\\Windows\\SysWOW64\\iscsicpl.exe" and module.path contains "\\iscsiexe.dll") and (not (module.path contains "C:\\Windows\\" and module.path contains "iscsiexe.dll"))))
```


# Original Sigma Rule:
```yaml
title: UAC Bypass Using Iscsicpl - ImageLoad
id: 9ed5959a-c43c-4c59-84e3-d28628429456
status: test
description: Detects the "iscsicpl.exe" UAC bypass technique that leverages a DLL Search Order hijacking technique to load a custom DLL's from temp or a any user controlled location in the users %PATH%
references:
    - https://github.com/hackerhouse-opensource/iscsicpl_bypassUAC
    - https://twitter.com/wdormann/status/1547583317410607110
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-07-17
modified: 2022-07-25
tags:
    - attack.defense-evasion
    - attack.privilege-escalation
    - attack.t1548.002
logsource:
    product: windows
    category: image_load
detection:
    selection:
        Image: C:\Windows\SysWOW64\iscsicpl.exe
        ImageLoaded|endswith: '\iscsiexe.dll'
    filter:
        ImageLoaded|contains|all:
            - 'C:\Windows\'
            - 'iscsiexe.dll'
    condition: selection and not filter
falsepositives:
    - Unknown
level: high
```
