```sql
// Translated content (automatically translated on 22-12-2025 01:02:22):
event.type="Process Creation" and (endpoint.os="linux" and (src.process.cmdline="bash -i" and ((tgt.process.cmdline contains "-c import " or tgt.process.cmdline contains "base64" or tgt.process.cmdline contains "pty.spawn") or (tgt.process.image.path contains "whoami" or tgt.process.image.path contains "iptables" or tgt.process.image.path contains "/ncat" or tgt.process.image.path contains "/nc" or tgt.process.image.path contains "/netcat"))))
```


# Original Sigma Rule:
```yaml
title: Interactive Bash Suspicious Children
id: ea3ecad2-db86-4a89-ad0b-132a10d2db55
status: test
description: Detects suspicious interactive bash as a parent to rather uncommon child processes
references:
    - Internal Research
author: Florian Roth (Nextron Systems)
date: 2022-03-14
tags:
    - attack.execution
    - attack.defense-evasion
    - attack.t1059.004
    - attack.t1036
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        ParentCommandLine: 'bash -i'
    anomaly1:
        CommandLine|contains:
            - '-c import '
            - 'base64'
            - 'pty.spawn'
    anomaly2:
        Image|endswith:
            - 'whoami'
            - 'iptables'
            - '/ncat'
            - '/nc'
            - '/netcat'
    condition: selection and 1 of anomaly*
falsepositives:
    - Legitimate software that uses these patterns
level: medium
```
