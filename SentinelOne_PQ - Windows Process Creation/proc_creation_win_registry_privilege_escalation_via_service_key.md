```sql
// Translated content (automatically translated on 06-10-2024 07:02:16):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.integrityLevel="Medium" and (tgt.process.cmdline contains "ControlSet" and tgt.process.cmdline contains "services") and (tgt.process.cmdline contains "\ImagePath" or tgt.process.cmdline contains "\FailureCommand" or tgt.process.cmdline contains "\ServiceDll")))
```


# Original Sigma Rule:
```yaml
title: Potential Privilege Escalation via Service Permissions Weakness
id: 0f9c21f1-6a73-4b0e-9809-cb562cb8d981
status: test
description: Detect modification of services configuration (ImagePath, FailureCommand and ServiceDLL) in registry by processes with Medium integrity level
references:
    - https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment
    - https://pentestlab.blog/2017/03/31/insecure-registry-permissions/
author: Teymur Kheirkhabarov
date: 2019-10-26
modified: 2023-01-30
tags:
    - attack.privilege-escalation
    - attack.t1574.011
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        IntegrityLevel: 'Medium'
        CommandLine|contains|all:
            - 'ControlSet'
            - 'services'
        CommandLine|contains:
            - '\ImagePath'
            - '\FailureCommand'
            - '\ServiceDll'
    condition: selection
falsepositives:
    - Unknown
level: high
```