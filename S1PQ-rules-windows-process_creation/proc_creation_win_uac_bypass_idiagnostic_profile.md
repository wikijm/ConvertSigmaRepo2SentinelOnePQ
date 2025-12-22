```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\\DllHost.exe" and src.process.cmdline contains " /Processid:{12C21EA7-2EB8-4B55-9249-AC243DA8C666}" and (tgt.process.integrityLevel in ("High","System","S-1-16-16384","S-1-16-12288"))))
```


# Original Sigma Rule:
```yaml
title: UAC Bypass Using IDiagnostic Profile
id: 4cbef972-f347-4170-b62a-8253f6168e6d
status: test
description: Detects the "IDiagnosticProfileUAC" UAC bypass technique
references:
    - https://github.com/Wh04m1001/IDiagnosticProfileUAC
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-07-03
modified: 2024-12-01
tags:
    - attack.execution
    - attack.defense-evasion
    - attack.privilege-escalation
    - attack.t1548.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\DllHost.exe'
        ParentCommandLine|contains: ' /Processid:{12C21EA7-2EB8-4B55-9249-AC243DA8C666}'
        IntegrityLevel:
            - 'High'
            - 'System'
            - 'S-1-16-16384' # System
            - 'S-1-16-12288' # High
    condition: selection
falsepositives:
    - Unknown
level: high
```
