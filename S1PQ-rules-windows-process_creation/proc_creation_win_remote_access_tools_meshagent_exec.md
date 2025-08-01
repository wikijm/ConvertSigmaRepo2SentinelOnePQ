```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\meshagent.exe" and (tgt.process.image.path contains "\cmd.exe" or tgt.process.image.path contains "\powershell.exe" or tgt.process.image.path contains "\pwsh.exe")))
```


# Original Sigma Rule:
```yaml
title: Remote Access Tool - MeshAgent Command Execution via MeshCentral
id: 74a2b202-73e0-4693-9a3a-9d36146d0775
status: experimental
description: |
    Detects the use of MeshAgent to execute commands on the target host, particularly when threat actors might abuse it to execute commands directly.
    MeshAgent can execute commands on the target host by leveraging win-console to obscure their activities and win-dispatcher to run malicious code through IPC with child processes.
references:
    - https://github.com/Ylianst/MeshAgent
    - https://github.com/Ylianst/MeshAgent/blob/52cf129ca43d64743181fbaf940e0b4ddb542a37/modules/win-dispatcher.js#L173
    - https://github.com/Ylianst/MeshAgent/blob/52cf129ca43d64743181fbaf940e0b4ddb542a37/modules/win-info.js#L55
author: '@Kostastsale'
date: 2024-09-22
tags:
    - attack.command-and-control
    - attack.t1219.002
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        ParentImage|endswith: '\meshagent.exe'
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
    condition: selection
falsepositives:
    - False positives can be found in environments using MeshAgent for remote management, analysis should prioritize the grandparent process, MeshAgent.exe, and scrutinize the resulting child processes triggered by any suspicious interactive commands directed at the target host.
level: medium
```
