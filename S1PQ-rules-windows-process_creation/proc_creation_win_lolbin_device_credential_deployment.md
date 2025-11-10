```sql
// Translated content (automatically translated on 10-11-2025 02:07:16):
event.type="Process Creation" and (endpoint.os="windows" and tgt.process.image.path contains "\\DeviceCredentialDeployment.exe")
```


# Original Sigma Rule:
```yaml
title: DeviceCredentialDeployment Execution
id: b8b1b304-a60f-4999-9a6e-c547bde03ffd
status: test
description: Detects the execution of DeviceCredentialDeployment to hide a process from view
references:
    - https://github.com/LOLBAS-Project/LOLBAS/pull/147
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-08-19
tags:
    - attack.defense-evasion
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\DeviceCredentialDeployment.exe'
    condition: selection
falsepositives:
    - Unlikely
level: medium
```
