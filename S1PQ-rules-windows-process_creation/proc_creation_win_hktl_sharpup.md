```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\\SharpUp.exe" or tgt.process.displayName="SharpUp" or (tgt.process.cmdline contains "HijackablePaths" or tgt.process.cmdline contains "UnquotedServicePath" or tgt.process.cmdline contains "ProcessDLLHijack" or tgt.process.cmdline contains "ModifiableServiceBinaries" or tgt.process.cmdline contains "ModifiableScheduledTask" or tgt.process.cmdline contains "DomainGPPPassword" or tgt.process.cmdline contains "CachedGPPPassword")))
```


# Original Sigma Rule:
```yaml
title: HackTool - SharpUp PrivEsc Tool Execution
id: c484e533-ee16-4a93-b6ac-f0ea4868b2f1
status: test
description: Detects the use of SharpUp, a tool for local privilege escalation
references:
    - https://github.com/GhostPack/SharpUp
author: Florian Roth (Nextron Systems)
date: 2022-08-20
modified: 2023-02-13
tags:
    - attack.persistence
    - attack.defense-evasion
    - attack.privilege-escalation
    - attack.discovery
    - attack.execution
    - attack.t1615
    - attack.t1569.002
    - attack.t1574.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\SharpUp.exe'
        - Description: 'SharpUp'
        - CommandLine|contains:
              - 'HijackablePaths'
              - 'UnquotedServicePath'
              - 'ProcessDLLHijack'
              - 'ModifiableServiceBinaries'
              - 'ModifiableScheduledTask'
              - 'DomainGPPPassword'
              - 'CachedGPPPassword'
    condition: selection
falsepositives:
    - Unknown
level: critical
```
