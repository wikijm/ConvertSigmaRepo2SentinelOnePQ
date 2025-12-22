```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "WindowsAudioDevice-Powershell-Cmdlet" or tgt.process.cmdline contains "Toggle-AudioDevice" or tgt.process.cmdline contains "Get-AudioDevice " or tgt.process.cmdline contains "Set-AudioDevice " or tgt.process.cmdline contains "Write-AudioDevice "))
```


# Original Sigma Rule:
```yaml
title: Audio Capture via PowerShell
id: 932fb0d8-692b-4b0f-a26e-5643a50fe7d6
status: test
description: Detects audio capture via PowerShell Cmdlet.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1123/T1123.md
    - https://eqllib.readthedocs.io/en/latest/analytics/ab7a6ef4-0983-4275-a4f1-5c6bd3c31c23.html
    - https://github.com/frgnca/AudioDeviceCmdlets
author: E.M. Anhaus (originally from Atomic Blue Detections, Endgame), oscd.community, Nasreddine Bencherchali (Nextron Systems)
date: 2019-10-24
modified: 2023-04-06
tags:
    - attack.collection
    - attack.t1123
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'WindowsAudioDevice-Powershell-Cmdlet'
            - 'Toggle-AudioDevice'
            - 'Get-AudioDevice '
            - 'Set-AudioDevice '
            - 'Write-AudioDevice '
    condition: selection
falsepositives:
    - Legitimate audio capture by legitimate user.
level: medium
```
