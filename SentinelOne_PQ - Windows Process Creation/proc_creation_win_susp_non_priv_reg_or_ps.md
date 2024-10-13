```sql
// Translated content (automatically translated on 13-10-2024 01:24:17):
event.type="Process Creation" and (endpoint.os="windows" and (((tgt.process.cmdline contains "reg " and tgt.process.cmdline contains "add") or (tgt.process.cmdline contains "powershell" or tgt.process.cmdline contains "set-itemproperty" or tgt.process.cmdline contains " sp " or tgt.process.cmdline contains "new-itemproperty")) and (tgt.process.integrityLevel="Medium" and (tgt.process.cmdline contains "ControlSet" and tgt.process.cmdline contains "Services") and (tgt.process.cmdline contains "ImagePath" or tgt.process.cmdline contains "FailureCommand" or tgt.process.cmdline contains "ServiceDLL")))) | columns EventID,tgt.process.integrityLevel,tgt.process.cmdline
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
modified: 2022-07-07
tags:
    - attack.defense-evasion
    - attack.t1112
logsource:
    category: process_creation
    product: windows
detection:
    reg:
        CommandLine|contains|all:
            - 'reg '
            - 'add'
    powershell:
        CommandLine|contains:
            - 'powershell'
            - 'set-itemproperty'
            - ' sp '
            - 'new-itemproperty'
    select_data:
        IntegrityLevel: 'Medium'
        CommandLine|contains|all:
            - 'ControlSet'
            - 'Services'
        CommandLine|contains:
            - 'ImagePath'
            - 'FailureCommand'
            - 'ServiceDLL'
    condition: (reg or powershell) and select_data
fields:
    - EventID
    - IntegrityLevel
    - CommandLine
falsepositives:
    - Unknown
level: high
```
