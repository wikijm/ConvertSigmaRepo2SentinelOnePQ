```sql
// Translated content (automatically translated on 10-11-2025 02:07:16):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\\CustomShellHost.exe" and (not tgt.process.image.path="C:\\Windows\\explorer.exe")))
```


# Original Sigma Rule:
```yaml
title: Suspicious CustomShellHost Execution
id: 84b14121-9d14-416e-800b-f3b829c5a14d
status: test
description: Detects the execution of CustomShellHost binary where the child isn't located in 'C:\Windows\explorer.exe'
references:
    - https://github.com/LOLBAS-Project/LOLBAS/pull/180
    - https://lolbas-project.github.io/lolbas/Binaries/CustomShellHost/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-08-19
tags:
    - attack.defense-evasion
    - attack.t1216
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\CustomShellHost.exe'
    filter:
        Image: 'C:\Windows\explorer.exe'
    condition: selection and not filter
falsepositives:
    - Unknown
level: medium
```
