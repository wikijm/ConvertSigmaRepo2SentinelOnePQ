```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "New-Service" and tgt.process.cmdline contains "-BinaryPathName"))
```


# Original Sigma Rule:
```yaml
title: New Service Creation Using PowerShell
id: c02e96b7-c63a-4c47-bd83-4a9f74afcfb2
related:
    - id: 85ff530b-261d-48c6-a441-facaa2e81e48 # Using Sc.EXE
      type: similar
status: test
description: Detects the creation of a new service using powershell.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1543.003/T1543.003.md
author: Timur Zinniatullin, Daniil Yugoslavskiy, oscd.community
date: 2023-02-20
tags:
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1543.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'New-Service'
            - '-BinaryPathName'
    condition: selection
falsepositives:
    - Legitimate administrator or user creates a service for legitimate reasons.
    - Software installation
level: low
```
