```sql
// Translated content (automatically translated on 10-02-2025 01:20:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "accepteula" and tgt.process.cmdline contains " -u " and tgt.process.cmdline contains " -p " and tgt.process.cmdline contains " \\"))
```


# Original Sigma Rule:
```yaml
title: Potential PsExec Remote Execution
id: ea011323-7045-460b-b2d7-0f7442ea6b38
status: test
description: Detects potential psexec command that initiate execution on a remote systems via common commandline flags used by the utility
references:
    - https://learn.microsoft.com/en-us/sysinternals/downloads/psexec
    - https://www.poweradmin.com/paexec/
    - https://www.fireeye.com/blog/threat-research/2020/10/kegtap-and-singlemalt-with-a-ransomware-chaser.html
author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
date: 2023-02-28
tags:
    - attack.resource-development
    - attack.t1587.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        # Accepting EULA in commandline - often used in automated attacks
        CommandLine|contains|all:
            - 'accepteula'
            - ' -u '
            - ' -p '
            - ' \\\\'
    condition: selection
falsepositives:
    - Unknown
level: high
```
