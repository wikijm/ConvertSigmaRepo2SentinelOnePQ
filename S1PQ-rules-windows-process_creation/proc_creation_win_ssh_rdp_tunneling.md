```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\ssh.exe" and tgt.process.cmdline contains ":3389"))
```


# Original Sigma Rule:
```yaml
title: Potential RDP Tunneling Via SSH
id: f7d7ebd5-a016-46e2-9c54-f9932f2d386d
related:
    - id: f38ce0b9-5e97-4b47-a211-7dc8d8b871da # plink.exe
      type: similar
status: test
description: Execution of ssh.exe to perform data exfiltration and tunneling through RDP
references:
    - https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-10-12
modified: 2023-01-25
tags:
    - attack.command-and-control
    - attack.t1572
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\ssh.exe'
        CommandLine|contains: ':3389'
    condition: selection
falsepositives:
    - Unknown
level: high
```
