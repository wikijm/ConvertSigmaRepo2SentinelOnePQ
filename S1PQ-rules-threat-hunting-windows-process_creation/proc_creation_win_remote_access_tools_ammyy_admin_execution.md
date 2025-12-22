```sql
// Translated content (automatically translated on 22-12-2025 00:55:34):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\\rundll32.exe" and tgt.process.cmdline contains "AMMYY\\aa_nts.dll\",run"))
```


# Original Sigma Rule:
```yaml
title: Remote Access Tool - Ammy Admin Agent Execution
id: 7da7809e-f3d5-47a3-9d5d-fc9d019caf14
status: test
description: Detects the execution of the Ammy Admin RMM agent for remote management.
references:
    - https://www.ammyy.com/en/admin_features.html
author: '@kostastsale'
date: 2024-08-05
tags:
    - attack.execution
    - attack.persistence
    - detection.threat-hunting
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\rundll32.exe'
        CommandLine|contains: 'AMMYY\aa_nts.dll",run'
    condition: selection
falsepositives:
    - Legitimate use of Ammy Admin RMM agent for remote management by admins.
level: medium
```
