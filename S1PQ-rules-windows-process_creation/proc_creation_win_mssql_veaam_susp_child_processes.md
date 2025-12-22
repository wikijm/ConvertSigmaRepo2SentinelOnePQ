```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\\sqlservr.exe" and src.process.cmdline contains "VEEAMSQL") and (((tgt.process.image.path contains "\\cmd.exe" or tgt.process.image.path contains "\\powershell.exe" or tgt.process.image.path contains "\\pwsh.exe" or tgt.process.image.path contains "\\wsl.exe" or tgt.process.image.path contains "\\wt.exe") and (tgt.process.cmdline contains "-ex " or tgt.process.cmdline contains "bypass" or tgt.process.cmdline contains "cscript" or tgt.process.cmdline contains "DownloadString" or tgt.process.cmdline contains "http://" or tgt.process.cmdline contains "https://" or tgt.process.cmdline contains "mshta" or tgt.process.cmdline contains "regsvr32" or tgt.process.cmdline contains "rundll32" or tgt.process.cmdline contains "wscript" or tgt.process.cmdline contains "copy ")) or (tgt.process.image.path contains "\\net.exe" or tgt.process.image.path contains "\\net1.exe" or tgt.process.image.path contains "\\netstat.exe" or tgt.process.image.path contains "\\nltest.exe" or tgt.process.image.path contains "\\ping.exe" or tgt.process.image.path contains "\\tasklist.exe" or tgt.process.image.path contains "\\whoami.exe"))))
```


# Original Sigma Rule:
```yaml
title: Suspicious Child Process Of Veeam Dabatase
id: d55b793d-f847-4eea-b59a-5ab09908ac90
related:
    - id: 869b9ca7-9ea2-4a5a-8325-e80e62f75445
      type: similar
status: test
description: Detects suspicious child processes of the Veeam service process. This could indicate potential RCE or SQL Injection.
references:
    - https://labs.withsecure.com/publications/fin7-target-veeam-servers
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-05-04
tags:
    - attack.initial-access
    - attack.persistence
    - attack.privilege-escalation
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\sqlservr.exe'
        ParentCommandLine|contains: 'VEEAMSQL'
    selection_child_1:
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\wsl.exe'
            - '\wt.exe'
        CommandLine|contains:
            - '-ex '
            - 'bypass'
            - 'cscript'
            - 'DownloadString'
            - 'http://'
            - 'https://'
            - 'mshta'
            - 'regsvr32'
            - 'rundll32'
            - 'wscript'
            - 'copy '
    selection_child_2:
        Image|endswith:
            - '\net.exe'
            - '\net1.exe'
            - '\netstat.exe'
            - '\nltest.exe'
            - '\ping.exe'
            - '\tasklist.exe'
            - '\whoami.exe'
    condition: selection_parent and 1 of selection_child_*
level: critical
```
