```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\powershell.exe" or tgt.process.image.path contains "\pwsh.exe") and tgt.process.cmdline matches "\\s-\\s*<"))
```


# Original Sigma Rule:
```yaml
title: Run PowerShell Script from Redirected Input Stream
id: c83bf4b5-cdf0-437c-90fa-43d734f7c476
status: test
description: Detects PowerShell script execution via input stream redirect
references:
    - https://github.com/LOLBAS-Project/LOLBAS/blob/4db780e0f0b2e2bb8cb1fa13e09196da9b9f1834/yml/LOLUtilz/OSBinaries/Powershell.yml
    - https://twitter.com/Moriarty_Meng/status/984380793383370752
author: Moriarty Meng (idea), Anton Kutepov (rule), oscd.community
date: 2020-10-17
modified: 2021-11-27
tags:
    - attack.defense-evasion
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
        CommandLine|re: '\s-\s*<'
    condition: selection
falsepositives:
    - Unknown
level: high
```
