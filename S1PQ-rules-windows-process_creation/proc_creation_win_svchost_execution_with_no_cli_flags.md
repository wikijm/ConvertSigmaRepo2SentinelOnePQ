```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains "svchost.exe" and tgt.process.image.path contains "\svchost.exe") and (not ((src.process.image.path contains "\rpcnet.exe" or src.process.image.path contains "\rpcnetp.exe") or not (tgt.process.cmdline matches "\.*"))))) | columns tgt.process.cmdline,src.process.cmdline
```


# Original Sigma Rule:
```yaml
title: Suspect Svchost Activity
id: 16c37b52-b141-42a5-a3ea-bbe098444397
status: test
description: It is extremely abnormal for svchost.exe to spawn without any CLI arguments and is normally observed when a malicious process spawns the process and injects code into the process memory space.
references:
    - https://web.archive.org/web/20180718061628/https://securitybytes.io/blue-team-fundamentals-part-two-windows-processes-759fe15965e2
author: David Burkett, @signalblur
date: 2019-12-28
modified: 2022-06-27
tags:
    - attack.defense-evasion
    - attack.privilege-escalation
    - attack.t1055
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|endswith: 'svchost.exe'
        Image|endswith: '\svchost.exe'
    filter:
        - ParentImage|endswith:
              - '\rpcnet.exe'
              - '\rpcnetp.exe'
        - CommandLine: null  # no CommandLine value available
    condition: selection and not filter
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Rpcnet.exe / rpcnetp.exe which is a lojack style software. https://www.blackhat.com/docs/us-14/materials/us-14-Kamlyuk-Kamluk-Computrace-Backdoor-Revisited.pdf
level: high
```
