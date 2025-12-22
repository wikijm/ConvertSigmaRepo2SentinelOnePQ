```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\\sc.exe" and (tgt.process.cmdline contains "create" or tgt.process.cmdline contains "config") and (tgt.process.cmdline contains "binPath" and tgt.process.cmdline contains "type" and tgt.process.cmdline contains "kernel")) and (not ((tgt.process.cmdline contains "create netprotection_network_filter" and tgt.process.cmdline contains "type= kernel start= " and tgt.process.cmdline contains "binPath= System32\\drivers\\netprotection_network_filter" and tgt.process.cmdline contains "DisplayName= netprotection_network_filter" and tgt.process.cmdline contains "group= PNP_TDI tag= yes") or (tgt.process.cmdline contains "create avelam binpath=C:\\Windows\\system32\\drivers\\avelam.sys" and tgt.process.cmdline contains "type=kernel start=boot error=critical group=Early-Launch")))))
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
modified: 2025-10-07
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
    filter_optional_avira_driver:
        - CommandLine|contains|all:
              - 'create netprotection_network_filter'
              - 'type= kernel start= '
              - 'binPath= System32\drivers\netprotection_network_filter'
              - 'DisplayName= netprotection_network_filter'
              - 'group= PNP_TDI tag= yes'
        - CommandLine|contains|all:
              - 'create avelam binpath=C:\Windows\system32\drivers\avelam.sys'
              - 'type=kernel start=boot error=critical group=Early-Launch'
    condition: selection and not 1 of filter_optional_*
falsepositives:
    - Rare legitimate installation of kernel drivers via sc.exe
level: medium
```
