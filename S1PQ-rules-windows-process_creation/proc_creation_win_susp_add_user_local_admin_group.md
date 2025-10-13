```sql
// Translated content (automatically translated on 13-10-2025 02:01:30):
event.type="Process Creation" and (endpoint.os="windows" and (((tgt.process.cmdline contains "localgroup " and tgt.process.cmdline contains " /add") or (tgt.process.cmdline contains "Add-LocalGroupMember " and tgt.process.cmdline contains " -Group ")) and (tgt.process.cmdline contains " administrators " or tgt.process.cmdline contains " administrateur")))
```


# Original Sigma Rule:
```yaml
title: User Added to Local Administrators Group
id: ad720b90-25ad-43ff-9b5e-5c841facc8e5
related:
    - id: ffa28e60-bdb1-46e0-9f82-05f7a61cc06e # Remote Desktop groups
      type: similar
    - id: 10fb649c-3600-4d37-b1e6-56ea90bb7e09 # Privileged groups
      type: similar
status: test
description: Detects addition of users to the local administrator group via "Net" or "Add-LocalGroupMember".
references:
    - https://blog.talosintelligence.com/2022/08/recent-cyber-attack.html?m=1
author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
date: 2022-08-12
modified: 2023-03-02
tags:
    - attack.persistence
    - attack.t1098
logsource:
    category: process_creation
    product: windows
detection:
    selection_main:
        - CommandLine|contains|all:
              # net.exe
              - 'localgroup '
              - ' /add'
        - CommandLine|contains|all:
              # powershell.exe
              - 'Add-LocalGroupMember '
              - ' -Group '
    selection_group:
        CommandLine|contains:
            - ' administrators '
            - ' administrateur' # Typo without an 'S' so we catch both
    condition: all of selection_*
falsepositives:
    - Administrative activity
level: medium
```
