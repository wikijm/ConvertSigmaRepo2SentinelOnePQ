```sql
// Translated content (automatically translated on 20-06-2025 02:06:09):
event.type="Process Creation" and (endpoint.os="windows" and ((not (tgt.process.image.path contains "C:\Windows\System32\" or tgt.process.image.path contains "C:\Windows\SysWOW64\")) and (src.process.cmdline contains "cmd.exe /c" and src.process.cmdline contains "RoamDiag.cmd" and src.process.cmdline contains "-outputpath"))) | columns TargetFilename,tgt.process.image.path
```


# Original Sigma Rule:
```yaml
title: Using SettingSyncHost.exe as LOLBin
id: b2ddd389-f676-4ac4-845a-e00781a48e5f
status: test
description: Detects using SettingSyncHost.exe to run hijacked binary
references:
    - https://www.hexacorn.com/blog/2020/02/02/settingsynchost-exe-as-a-lolbin
author: Anton Kutepov, oscd.community
date: 2020-02-05
modified: 2021-11-27
tags:
    - attack.execution
    - attack.defense-evasion
    - attack.t1574.008
logsource:
    category: process_creation
    product: windows
detection:
    system_utility:
        Image|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Windows\SysWOW64\'
    parent_is_settingsynchost:
        ParentCommandLine|contains|all:
            - 'cmd.exe /c'
            - 'RoamDiag.cmd'
            - '-outputpath'
    condition: not system_utility and parent_is_settingsynchost
fields:
    - TargetFilename
    - Image
falsepositives:
    - Unknown
level: high
```
