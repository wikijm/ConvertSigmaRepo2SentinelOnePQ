```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\\wsmprovhost.exe" and (tgt.process.image.path contains "\\cmd.exe" or tgt.process.image.path contains "\\sh.exe" or tgt.process.image.path contains "\\bash.exe" or tgt.process.image.path contains "\\powershell.exe" or tgt.process.image.path contains "\\pwsh.exe" or tgt.process.image.path contains "\\wsl.exe" or tgt.process.image.path contains "\\schtasks.exe" or tgt.process.image.path contains "\\certutil.exe" or tgt.process.image.path contains "\\whoami.exe" or tgt.process.image.path contains "\\bitsadmin.exe")))
```


# Original Sigma Rule:
```yaml
title: Suspicious Processes Spawned by WinRM
id: 5cc2cda8-f261-4d88-a2de-e9e193c86716
status: test
description: Detects suspicious processes including shells spawnd from WinRM host process
author: Andreas Hunkeler (@Karneades), Markus Neis
references:
    - Internal Research
date: 2021-05-20
modified: 2022-07-14
tags:
    - attack.t1190
    - attack.initial-access
    - attack.persistence
    - attack.privilege-escalation
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\wsmprovhost.exe'
        Image|endswith:
            - '\cmd.exe'
            - '\sh.exe'
            - '\bash.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\wsl.exe'
            - '\schtasks.exe'
            - '\certutil.exe'
            - '\whoami.exe'
            - '\bitsadmin.exe'
    condition: selection
falsepositives:
    - Legitimate WinRM usage
level: high
```
