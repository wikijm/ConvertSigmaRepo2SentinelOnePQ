```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy" and (tgt.process.cmdline contains "\NTDS.dit" or tgt.process.cmdline contains "\SYSTEM" or tgt.process.cmdline contains "\SECURITY")))
```


# Original Sigma Rule:
```yaml
title: Sensitive File Access Via Volume Shadow Copy Backup
id: f57f8d16-1f39-4dcb-a604-6c73d9b54b3d
status: test
description: |
    Detects a command that accesses the VolumeShadowCopy in order to extract sensitive files such as the Security or SAM registry hives or the AD database (ntds.dit)
references:
    - https://twitter.com/vxunderground/status/1423336151860002816?s=20
    - https://www.virustotal.com/gui/file/03e9b8c2e86d6db450e5eceec057d7e369ee2389b9daecaf06331a95410aa5f8/detection
    - https://pentestlab.blog/2018/07/04/dumping-domain-password-hashes/
author: Max Altgelt (Nextron Systems), Tobias Michalski (Nextron Systems)
date: 2021-08-09
modified: 2024-01-18
tags:
    - attack.impact
    - attack.t1490
logsource:
    category: process_creation
    product: windows
detection:
    selection_1:
        # copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\temp\ntds.dit 2>&1
        # There is an additional "\" to escape the special "?"
        CommandLine|contains: '\\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy'
    selection_2:
        CommandLine|contains:
            - '\\NTDS.dit'
            - '\\SYSTEM'
            - '\\SECURITY'
    condition: all of selection_*
falsepositives:
    - Unlikely
level: high
```
