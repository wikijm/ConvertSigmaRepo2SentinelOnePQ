```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\schtasks.exe" and (tgt.process.cmdline contains "/Change" and tgt.process.cmdline contains "/TN" and tgt.process.cmdline contains "/disable") and (tgt.process.cmdline contains "\Windows\BitLocker" or tgt.process.cmdline contains "\Windows\ExploitGuard" or tgt.process.cmdline contains "\Windows\ExploitGuard\ExploitGuard MDM policy Refresh" or tgt.process.cmdline contains "\Windows\SystemRestore\SR" or tgt.process.cmdline contains "\Windows\UpdateOrchestrator\" or tgt.process.cmdline contains "\Windows\Windows Defender\" or tgt.process.cmdline contains "\Windows\WindowsBackup\" or tgt.process.cmdline contains "\Windows\WindowsUpdate\")))
```


# Original Sigma Rule:
```yaml
title: Disable Important Scheduled Task
id: 9ac94dc8-9042-493c-ba45-3b5e7c86b980
related:
    - id: 7595ba94-cf3b-4471-aa03-4f6baa9e5fad # Security-Audting Eventlog
      type: similar
status: test
description: Detects when adversaries stop services or processes by disabling their respective scheduled tasks in order to conduct data destructive activities
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1490/T1490.md#atomic-test-8---windows---disable-the-sr-scheduled-task
    - https://twitter.com/MichalKoczwara/status/1553634816016498688
    - https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/
author: frack113, Nasreddine Bencherchali (Nextron Systems), X__Junior
date: 2021-12-26
modified: 2024-08-25
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
            - '/Change'
            - '/TN'
            - '/disable'
        CommandLine|contains:
            # Add more important tasks
            - '\Windows\BitLocker'
            - '\Windows\ExploitGuard'
            - '\Windows\ExploitGuard\ExploitGuard MDM policy Refresh'
            - '\Windows\SystemRestore\SR'
            - '\Windows\UpdateOrchestrator\'
            - '\Windows\Windows Defender\'
            - '\Windows\WindowsBackup\'
            - '\Windows\WindowsUpdate\'
    condition: selection
falsepositives:
    - Unknown
level: high
```
