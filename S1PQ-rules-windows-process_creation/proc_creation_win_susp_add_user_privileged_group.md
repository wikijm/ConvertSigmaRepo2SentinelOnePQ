```sql
// Translated content (automatically translated on 28-05-2025 02:04:17):
event.type="Process Creation" and (endpoint.os="windows" and (((tgt.process.cmdline contains "localgroup " and tgt.process.cmdline contains " /add") or (tgt.process.cmdline contains "Add-LocalGroupMember " and tgt.process.cmdline contains " -Group ")) and (tgt.process.cmdline contains "Group Policy Creator Owners" or tgt.process.cmdline contains "Schema Admins")))
```


# Original Sigma Rule:
```yaml
title: User Added To Highly Privileged Group
id: 10fb649c-3600-4d37-b1e6-56ea90bb7e09 # Privileged groups
related:
    - id: ffa28e60-bdb1-46e0-9f82-05f7a61cc06e # Remote Desktop groups
      type: similar
    - id: ad720b90-25ad-43ff-9b5e-5c841facc8e5 # Admin groups
      type: similar
status: test
description: Detects addition of users to highly privileged groups via "Net" or "Add-LocalGroupMember".
references:
    - https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708
author: Nasreddine Bencherchali (Nextron Systems)
date: 2024-02-23
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
            - 'Group Policy Creator Owners'
            - 'Schema Admins'
    condition: all of selection_*
falsepositives:
    - Administrative activity that must be investigated
level: high
```
