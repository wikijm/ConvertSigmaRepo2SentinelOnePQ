```sql
// Translated content (automatically translated on 19-10-2025 02:08:22):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\\schtasks.exe" and (tgt.process.cmdline contains "/delete" and tgt.process.cmdline contains "/tn") and (tgt.process.cmdline contains "\\Windows\\BitLocker" or tgt.process.cmdline contains "\\Windows\\ExploitGuard" or tgt.process.cmdline contains "\\Windows\\SystemRestore\\SR" or tgt.process.cmdline contains "\\Windows\\UpdateOrchestrator\\" or tgt.process.cmdline contains "\\Windows\\Windows Defender\\" or tgt.process.cmdline contains "\\Windows\\WindowsBackup\\" or tgt.process.cmdline contains "\\Windows\\WindowsUpdate\\")))
```


# Original Sigma Rule:
```yaml
title: Delete Important Scheduled Task
id: dbc1f800-0fe0-4bc0-9c66-292c2abe3f78
related:
    - id: 9e3cb244-bdb8-4632-8c90-6079c8f4f16d # TaskScheduler EventLog
      type: similar
    - id: 7595ba94-cf3b-4471-aa03-4f6baa9e5fad # Security-Audting Eventlog
      type: similar
status: test
description: Detects when adversaries stop services or processes by deleting their respective scheduled tasks in order to conduct data destructive activities
references:
    - Internal Research
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-09-09
tags:
    - attack.impact
    - attack.t1489
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains|all:
            - '/delete'
            - '/tn'
        CommandLine|contains:
            # Add more important tasks
            - '\Windows\BitLocker'
            - '\Windows\ExploitGuard'
            - '\Windows\SystemRestore\SR'
            - '\Windows\UpdateOrchestrator\'
            - '\Windows\Windows Defender\'
            - '\Windows\WindowsBackup\'
            - '\Windows\WindowsUpdate\'
    condition: selection
falsepositives:
    - Unlikely
level: high
```
