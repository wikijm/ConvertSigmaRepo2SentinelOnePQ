```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "Remove-MpPreference" and (tgt.process.cmdline contains "-ControlledFolderAccessProtectedFolders " or tgt.process.cmdline contains "-AttackSurfaceReductionRules_Ids " or tgt.process.cmdline contains "-AttackSurfaceReductionRules_Actions " or tgt.process.cmdline contains "-CheckForSignaturesBeforeRunningScan ")))
```


# Original Sigma Rule:
```yaml
title: Tamper Windows Defender Remove-MpPreference
id: 07e3cb2c-0608-410d-be4b-1511cb1a0448
related:
    - id: ae2bdd58-0681-48ac-be7f-58ab4e593458
      type: similar
status: test
description: Detects attempts to remove Windows Defender configurations using the 'MpPreference' cmdlet
references:
    - https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/windows-10-controlled-folder-access-event-search/ba-p/2326088
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-08-05
tags:
    - attack.defense-evasion
    - attack.t1562.001
logsource:
    product: windows
    category: process_creation
detection:
    selection_remove:
        CommandLine|contains: 'Remove-MpPreference'
    selection_tamper:
        CommandLine|contains:
            - '-ControlledFolderAccessProtectedFolders '
            - '-AttackSurfaceReductionRules_Ids '
            - '-AttackSurfaceReductionRules_Actions '
            - '-CheckForSignaturesBeforeRunningScan '
    condition: all of selection_*
falsepositives:
    - Legitimate PowerShell scripts
level: high
```
