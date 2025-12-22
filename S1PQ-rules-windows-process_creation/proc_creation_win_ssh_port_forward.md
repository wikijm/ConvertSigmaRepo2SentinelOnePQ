```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\\ssh.exe" and (tgt.process.cmdline contains " -R " or tgt.process.cmdline contains " /R " or tgt.process.cmdline contains " –R " or tgt.process.cmdline contains " —R " or tgt.process.cmdline contains " ―R ")))
```


# Original Sigma Rule:
```yaml
title: Port Forwarding Activity Via SSH.EXE
id: 327f48c1-a6db-4eb8-875a-f6981f1b0183
status: test
description: Detects port forwarding activity via SSH.exe
references:
    - https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-10-12
modified: 2024-03-05
tags:
    - attack.command-and-control
    - attack.lateral-movement
    - attack.t1572
    - attack.t1021.001
    - attack.t1021.004
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\ssh.exe'
        CommandLine|contains|windash: ' -R '
    condition: selection
falsepositives:
    - Administrative activity using a remote port forwarding to a local port
level: medium
```
