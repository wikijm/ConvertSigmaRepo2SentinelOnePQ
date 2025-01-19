```sql
// Translated content (automatically translated on 19-01-2025 01:23:06):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\sc.exe" and (tgt.process.cmdline contains "create" or tgt.process.cmdline contains "config") and (tgt.process.cmdline contains "binPath" and tgt.process.cmdline contains "type" and tgt.process.cmdline contains "kernel")))
```


# Original Sigma Rule:
```yaml
title: New Kernel Driver Via SC.EXE
id: 431a1fdb-4799-4f3b-91c3-a683b003fc49
status: test
description: Detects creation of a new service (kernel driver) with the type "kernel"
references:
    - https://www.aon.com/cyber-solutions/aon_cyber_labs/yours-truly-signed-av-driver-weaponizing-an-antivirus-driver/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-07-14
modified: 2022-08-08
tags:
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1543.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\sc.exe'
        CommandLine|contains:
            - 'create'
            - 'config'
        CommandLine|contains|all:
            - 'binPath'
            - 'type'
            - 'kernel'
    condition: selection
falsepositives:
    - Rare legitimate installation of kernel drivers via sc.exe
level: medium
```
