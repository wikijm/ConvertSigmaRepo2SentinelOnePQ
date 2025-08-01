```sql
// Translated content (automatically translated on 02-08-2025 01:23:14):
event.type="ModuleLoad" and (endpoint.os="windows" and ((module.path contains "C:\Windows\System32\logonUI.exe.local\" or module.path contains "C:\Windows\System32\werFault.exe.local\" or module.path contains "C:\Windows\System32\consent.exe.local\" or module.path contains "C:\Windows\System32\narrator.exe.local\" or module.path contains "C:\windows\system32\wermgr.exe.local\") and module.path contains "\comctl32.dll"))
```


# Original Sigma Rule:
```yaml
title: Potential DLL Sideloading Via comctl32.dll
id: 6360757a-d460-456c-8b13-74cf0e60cceb
status: test
description: Detects potential DLL sideloading using comctl32.dll to obtain system privileges
references:
    - https://github.com/binderlabs/DirCreate2System
    - https://github.com/sailay1996/awesome_windows_logical_bugs/blob/60cbb23a801f4c3195deac1cc46df27c225c3d07/dir_create2system.txt
author: Nasreddine Bencherchali (Nextron Systems), Subhash Popuri (@pbssubhash)
date: 2022-12-16
modified: 2022-12-19
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
        ImageLoaded|startswith:
            - 'C:\Windows\System32\logonUI.exe.local\'
            - 'C:\Windows\System32\werFault.exe.local\'
            - 'C:\Windows\System32\consent.exe.local\'
            - 'C:\Windows\System32\narrator.exe.local\'
            - 'C:\windows\system32\wermgr.exe.local\'
        ImageLoaded|endswith: '\comctl32.dll'
    condition: selection
falsepositives:
    - Unlikely
level: high
```
