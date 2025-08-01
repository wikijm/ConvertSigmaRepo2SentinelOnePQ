```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (((tgt.process.cmdline contains "localgroup " and tgt.process.cmdline contains " /add") or (tgt.process.cmdline contains "Add-LocalGroupMember " and tgt.process.cmdline contains " -Group ")) and (tgt.process.cmdline contains "Remote Desktop Users" or tgt.process.cmdline contains "Utilisateurs du Bureau à distance" or tgt.process.cmdline contains "Usuarios de escritorio remoto")))
```


# Original Sigma Rule:
```yaml
title: User Added to Remote Desktop Users Group
id: ffa28e60-bdb1-46e0-9f82-05f7a61cc06e
related:
    - id: ad720b90-25ad-43ff-9b5e-5c841facc8e5 # Admin groups
      type: similar
    - id: 10fb649c-3600-4d37-b1e6-56ea90bb7e09 # Privileged groups
      type: similar
status: test
description: Detects addition of users to the local Remote Desktop Users group via "Net" or "Add-LocalGroupMember".
references:
    - https://www.microsoft.com/security/blog/2021/11/16/evolving-trends-in-iranian-threat-actor-activity-mstic-presentation-at-cyberwarcon-2021/
author: Florian Roth (Nextron Systems)
date: 2021-12-06
modified: 2022-09-09
tags:
    - attack.persistence
    - attack.lateral-movement
    - attack.t1133
    - attack.t1136.001
    - attack.t1021.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_main:
        - CommandLine|contains|all:
              - 'localgroup '
              - ' /add'
        - CommandLine|contains|all:
              - 'Add-LocalGroupMember '
              - ' -Group '
    selection_group:
        CommandLine|contains:
            - 'Remote Desktop Users'
            - 'Utilisateurs du Bureau à distance' # French for "Remote Desktop Users"
            - 'Usuarios de escritorio remoto' # Spanish for "Remote Desktop Users"
    condition: all of selection_*
falsepositives:
    - Administrative activity
level: high
```
