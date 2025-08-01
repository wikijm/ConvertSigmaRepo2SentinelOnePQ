```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains "Add-MpPreference " or tgt.process.cmdline contains "Set-MpPreference ") and (tgt.process.cmdline contains " -ExclusionPath " or tgt.process.cmdline contains " -ExclusionExtension " or tgt.process.cmdline contains " -ExclusionProcess " or tgt.process.cmdline contains " -ExclusionIpAddress ")))
```


# Original Sigma Rule:
```yaml
title: Powershell Defender Exclusion
id: 17769c90-230e-488b-a463-e05c08e9d48f
related:
    - id: c1344fa2-323b-4d2e-9176-84b4d4821c88
      type: similar
status: test
description: Detects requests to exclude files, folders or processes from Antivirus scanning using PowerShell cmdlets
references:
    - https://learn.microsoft.com/en-us/defender-endpoint/configure-process-opened-file-exclusions-microsoft-defender-antivirus
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.001/T1562.001.md
    - https://twitter.com/AdamTheAnalyst/status/1483497517119590403
author: Florian Roth (Nextron Systems)
date: 2021-04-29
modified: 2022-05-12
tags:
    - attack.defense-evasion
    - attack.t1562.001
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine|contains:
            - 'Add-MpPreference '
            - 'Set-MpPreference '
    selection2:
        CommandLine|contains:
            - ' -ExclusionPath '
            - ' -ExclusionExtension '
            - ' -ExclusionProcess '
            - ' -ExclusionIpAddress '
    condition: all of selection*
falsepositives:
    - Possible Admin Activity
    - Other Cmdlets that may use the same parameters
level: medium
```
