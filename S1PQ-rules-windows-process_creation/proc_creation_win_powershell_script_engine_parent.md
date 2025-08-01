```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (((src.process.image.path contains "\wscript.exe" or src.process.image.path contains "\cscript.exe") and (tgt.process.image.path contains "\powershell.exe" or tgt.process.image.path contains "\pwsh.exe")) and (not tgt.process.image.path contains "\Health Service State\")))
```


# Original Sigma Rule:
```yaml
title: Suspicious PowerShell Invocation From Script Engines
id: 95eadcb2-92e4-4ed1-9031-92547773a6db
status: test
description: Detects suspicious powershell invocations from interpreters or unusual programs
references:
    - https://www.securitynewspaper.com/2017/03/20/attackers-leverage-excel-powershell-dns-latest-non-malware-attack/
author: Florian Roth (Nextron Systems)
date: 2019-01-16
modified: 2023-01-05
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith:
            - '\wscript.exe'
            - '\cscript.exe'
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
    filter_health_service:
        CurrentDirectory|contains: '\Health Service State\'
    condition: selection and not 1 of filter_*
falsepositives:
    - Microsoft Operations Manager (MOM)
    - Other scripts
level: medium
```
