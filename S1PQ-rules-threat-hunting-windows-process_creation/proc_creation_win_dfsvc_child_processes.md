```sql
// Translated content (automatically translated on 02-08-2025 00:52:11):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\dfsvc.exe" and tgt.process.image.path contains "\AppData\Local\Apps\2.0\"))
```


# Original Sigma Rule:
```yaml
title: ClickOnce Deployment Execution - Dfsvc.EXE Child Process
id: 241d52b5-eee0-49d0-ac8a-8b9c15c7221c
status: test
description: Detects child processes of "dfsvc" which indicates a ClickOnce deployment execution.
references:
    - https://posts.specterops.io/less-smartscreen-more-caffeine-ab-using-clickonce-for-trusted-code-execution-1446ea8051c5
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-06-12
tags:
    - attack.execution
    - attack.defense-evasion
    - detection.threat-hunting
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\dfsvc.exe'
        Image|endswith: '\AppData\Local\Apps\2.0\'
    condition: selection
falsepositives:
    - False positives are expected in environement leveraging ClickOnce deployments. An initial baselining is required before using this rule in production.
level: medium
```
