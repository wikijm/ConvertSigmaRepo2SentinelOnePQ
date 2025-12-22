```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains "echo " or tgt.process.cmdline contains "copy " or tgt.process.cmdline contains "type " or tgt.process.cmdline contains "file createnew") and (tgt.process.cmdline contains " C:\\Windows\\System32\\Tasks\\" or tgt.process.cmdline contains " C:\\Windows\\SysWow64\\Tasks\\")))
```


# Original Sigma Rule:
```yaml
title: Tasks Folder Evasion
id: cc4e02ba-9c06-48e2-b09e-2500cace9ae0
status: test
description: |
    The Tasks folder in system32 and syswow64 are globally writable paths.
    Adversaries can take advantage of this and load or influence any script hosts or ANY .NET Application
    in Tasks to load and execute a custom assembly into cscript, wscript, regsvr32, mshta, eventvwr
references:
    - https://twitter.com/subTee/status/1216465628946563073
    - https://gist.github.com/am0nsec/8378da08f848424e4ab0cc5b317fdd26
author: Sreeman
date: 2020-01-13
modified: 2022-12-25
tags:
    - attack.privilege-escalation
    - attack.defense-evasion
    - attack.persistence
    - attack.execution
    - attack.t1574.001
logsource:
    product: windows
    category: process_creation
detection:
    selection1:
        CommandLine|contains:
            - 'echo '
            - 'copy '
            - 'type '
            - 'file createnew'
    selection2:
        CommandLine|contains:
            - ' C:\Windows\System32\Tasks\'
            - ' C:\Windows\SysWow64\Tasks\'
    condition: all of selection*
falsepositives:
    - Unknown
level: high
```
