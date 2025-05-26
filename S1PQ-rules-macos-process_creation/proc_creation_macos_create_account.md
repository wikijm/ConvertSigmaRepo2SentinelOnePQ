```sql
// Translated content (automatically translated on 26-05-2025 01:20:44):
event.type="Process Creation" and (endpoint.os="osx" and ((tgt.process.image.path contains "/dscl" and tgt.process.cmdline contains "create") or (tgt.process.image.path contains "/sysadminctl" and tgt.process.cmdline contains "addUser")))
```


# Original Sigma Rule:
```yaml
title: Creation Of A Local User Account
id: 51719bf5-e4fd-4e44-8ba8-b830e7ac0731
status: test
description: Detects the creation of a new user account. Such accounts may be used for persistence that do not require persistent remote access tools to be deployed on the system.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1136.001/T1136.001.md
    - https://ss64.com/osx/sysadminctl.html
author: Alejandro Ortuno, oscd.community
date: 2020-10-06
modified: 2023-02-18
tags:
    - attack.t1136.001
    - attack.persistence
logsource:
    category: process_creation
    product: macos
detection:
    selection_dscl:
        Image|endswith: '/dscl'
        CommandLine|contains: 'create'
    selection_sysadminctl:
        Image|endswith: '/sysadminctl'
        CommandLine|contains: 'addUser'
    condition: 1 of selection_*
falsepositives:
    - Legitimate administration activities
level: low
```
