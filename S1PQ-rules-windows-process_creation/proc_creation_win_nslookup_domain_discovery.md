```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "nslookup" and tgt.process.cmdline contains "_ldap._tcp.dc._msdcs."))
```


# Original Sigma Rule:
```yaml
title: Network Reconnaissance Activity
id: e6313acd-208c-44fc-a0ff-db85d572e90e
status: test
description: Detects a set of suspicious network related commands often used in recon stages
references:
    - https://thedfirreport.com/2022/02/07/qbot-likes-to-move-it-move-it/
author: Florian Roth (Nextron Systems)
date: 2022-02-07
tags:
    - attack.discovery
    - attack.t1087
    - attack.t1082
    - car.2016-03-001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'nslookup'
            - '_ldap._tcp.dc._msdcs.'
    condition: selection
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
level: high
```
