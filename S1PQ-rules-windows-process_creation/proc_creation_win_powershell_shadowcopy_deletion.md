```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains "Get-WmiObject" or tgt.process.cmdline contains "gwmi" or tgt.process.cmdline contains "Get-CimInstance" or tgt.process.cmdline contains "gcim") and tgt.process.cmdline contains "Win32_ShadowCopy" and (tgt.process.cmdline contains ".Delete()" or tgt.process.cmdline contains "Remove-WmiObject" or tgt.process.cmdline contains "rwmi" or tgt.process.cmdline contains "Remove-CimInstance" or tgt.process.cmdline contains "rcim")))
```


# Original Sigma Rule:
```yaml
title: Deletion of Volume Shadow Copies via WMI with PowerShell
id: 21ff4ca9-f13a-41ad-b828-0077b2af2e40
related:
    - id: e17121b4-ef2a-4418-8a59-12fb1631fa9e
      type: derived
    - id: c1337eb8-921a-4b59-855b-4ba188ddcc42
      type: similar
status: test
description: Detects deletion of Windows Volume Shadow Copies with PowerShell code and Get-WMIObject. This technique is used by numerous ransomware families such as Sodinokibi/REvil
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1490/T1490.md#atomic-test-5---windows---delete-volume-shadow-copies-via-wmi-with-powershell
    - https://www.elastic.co/guide/en/security/current/volume-shadow-copy-deletion-via-powershell.html
author: Tim Rauch, Elastic (idea)
date: 2022-09-20
modified: 2022-12-30
tags:
    - attack.impact
    - attack.t1490
logsource:
    category: process_creation
    product: windows
detection:
    selection_get:
        CommandLine|contains:
            - 'Get-WmiObject'
            - 'gwmi'
            - 'Get-CimInstance'
            - 'gcim'
    selection_shadowcopy:
        CommandLine|contains: 'Win32_ShadowCopy'
    selection_delete:
        CommandLine|contains:
            - '.Delete()'
            - 'Remove-WmiObject'
            - 'rwmi'
            - 'Remove-CimInstance'
            - 'rcim'
    condition: all of selection*
falsepositives:
    - Unknown
level: high
```
