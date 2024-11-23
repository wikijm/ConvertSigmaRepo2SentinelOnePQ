```sql
// Translated content (automatically translated on 23-11-2024 01:20:43):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "\"\system32\cleanmgr.exe /autoclean /d C:" and src.process.cmdline="C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule" and (tgt.process.integrityLevel in ("High","System"))))
```


# Original Sigma Rule:
```yaml
title: UAC Bypass Using Disk Cleanup
id: b697e69c-746f-4a86-9f59-7bfff8eab881
status: test
description: Detects the pattern of UAC Bypass using scheduled tasks and variable expansion of cleanmgr.exe (UACMe 34)
references:
    - https://github.com/hfiref0x/UACME
author: Christian Burkard (Nextron Systems)
date: 2021-08-30
modified: 2022-10-09
tags:
    - attack.defense-evasion
    - attack.privilege-escalation
    - attack.t1548.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|endswith: '"\system32\cleanmgr.exe /autoclean /d C:'
        ParentCommandLine: 'C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule'
        IntegrityLevel:
            - 'High'
            - 'System'
    condition: selection
falsepositives:
    - Unknown
level: high
```
