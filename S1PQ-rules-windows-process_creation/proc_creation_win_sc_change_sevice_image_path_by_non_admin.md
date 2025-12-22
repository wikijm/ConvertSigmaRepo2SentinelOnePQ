```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\\sc.exe" and (tgt.process.integrityLevel in ("Medium","S-1-16-8192"))) and ((tgt.process.cmdline contains "config" and tgt.process.cmdline contains "binPath") or (tgt.process.cmdline contains "failure" and tgt.process.cmdline contains "command"))))
```


# Original Sigma Rule:
```yaml
title: Possible Privilege Escalation via Weak Service Permissions
id: d937b75f-a665-4480-88a5-2f20e9f9b22a
status: test
description: Detection of sc.exe utility spawning by user with Medium integrity level to change service ImagePath or FailureCommand
references:
    - https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment
    - https://pentestlab.blog/2017/03/30/weak-service-permissions/
author: Teymur Kheirkhabarov
date: 2019-10-26
modified: 2024-12-01
tags:
    - attack.persistence
    - attack.defense-evasion
    - attack.privilege-escalation
    - attack.t1574.011
logsource:
    category: process_creation
    product: windows
detection:
    scbynonadmin:
        Image|endswith: '\sc.exe'
        IntegrityLevel:
            - 'Medium'
            - 'S-1-16-8192'
    selection_binpath:
        CommandLine|contains|all:
            - 'config'
            - 'binPath'
    selection_failure:
        CommandLine|contains|all:
            - 'failure'
            - 'command'
    condition: scbynonadmin and 1 of selection_*
falsepositives:
    - Unknown
level: high
```
