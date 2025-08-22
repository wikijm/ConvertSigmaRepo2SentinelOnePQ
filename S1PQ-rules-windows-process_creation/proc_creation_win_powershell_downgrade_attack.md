```sql
// Translated content (automatically translated on 22-08-2025 01:59:59):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\\powershell.exe" and (tgt.process.cmdline contains " -version 2 " or tgt.process.cmdline contains " -versio 2 " or tgt.process.cmdline contains " -versi 2 " or tgt.process.cmdline contains " -vers 2 " or tgt.process.cmdline contains " -ver 2 " or tgt.process.cmdline contains " -ve 2 " or tgt.process.cmdline contains " -v 2 ")))
```


# Original Sigma Rule:
```yaml
title: Potential PowerShell Downgrade Attack
id: b3512211-c67e-4707-bedc-66efc7848863
related:
    - id: 6331d09b-4785-4c13-980f-f96661356249
      type: derived
status: test
description: Detects PowerShell downgrade attack by comparing the host versions with the actually used engine version 2.0
references:
    - http://www.leeholmes.com/blog/2017/03/17/detecting-and-preventing-powershell-downgrade-attacks/
    - https://github.com/r00t-3xp10it/hacking-material-books/blob/43cb1e1932c16ff1f58b755bc9ab6b096046853f/obfuscation/simple_obfuscation.md#bypass-or-avoid-amsi-by-version-downgrade-
author: Harish Segar (rule)
date: 2020-03-20
modified: 2023-01-04
tags:
    - attack.defense-evasion
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains:
            - ' -version 2 '
            - ' -versio 2 '
            - ' -versi 2 '
            - ' -vers 2 '
            - ' -ver 2 '
            - ' -ve 2 '
            - ' -v 2 '
    condition: selection
falsepositives:
    - Unknown
level: medium
```
