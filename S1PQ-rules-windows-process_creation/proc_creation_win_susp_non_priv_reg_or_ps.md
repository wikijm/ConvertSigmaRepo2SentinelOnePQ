```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (((tgt.process.cmdline contains "reg " and tgt.process.cmdline contains "add") or (tgt.process.cmdline contains "powershell" or tgt.process.cmdline contains "set-itemproperty" or tgt.process.cmdline contains " sp " or tgt.process.cmdline contains "new-itemproperty")) and ((tgt.process.integrityLevel in ("Medium","S-1-16-8192")) and (tgt.process.cmdline contains "ControlSet" and tgt.process.cmdline contains "Services") and (tgt.process.cmdline contains "ImagePath" or tgt.process.cmdline contains "FailureCommand" or tgt.process.cmdline contains "ServiceDLL"))))
```


# Original Sigma Rule:
```yaml
title: Non-privileged Usage of Reg or Powershell
id: 8f02c935-effe-45b3-8fc9-ef8696a9e41d
status: test
description: Search for usage of reg or Powershell by non-privileged users to modify service configuration in registry
references:
    - https://image.slidesharecdn.com/kheirkhabarovoffzonefinal-181117201458/95/hunting-for-privilege-escalation-in-windows-environment-20-638.jpg
author: Teymur Kheirkhabarov (idea), Ryan Plas (rule), oscd.community
date: 2020-10-05
modified: 2024-12-01
tags:
    - attack.persistence
    - attack.defense-evasion
    - attack.t1112
logsource:
    category: process_creation
    product: windows
detection:
    selection_cli:
        - CommandLine|contains|all:
              - 'reg '
              - 'add'
        - CommandLine|contains:
              - 'powershell'
              - 'set-itemproperty'
              - ' sp '
              - 'new-itemproperty'
    selection_data:
        IntegrityLevel:
            - 'Medium'
            - 'S-1-16-8192'
        CommandLine|contains|all:
            - 'ControlSet'
            - 'Services'
        CommandLine|contains:
            - 'ImagePath'
            - 'FailureCommand'
            - 'ServiceDLL'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
```
