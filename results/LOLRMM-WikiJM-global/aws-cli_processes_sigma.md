```sql
// Translated content (automatically translated on 02-08-2025 01:45:23):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "\AWSCLISetup.exe")
```


# Original Sigma Rule:
```yaml
title: Potential aws-cli RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - '*\AWSCLISetup.exe'
  condition: selection
id: 4e09548c-79e4-487e-9d0a-03cd67827b7d
status: experimental
description: Detects potential processes activity of aws-cli RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of aws-cli
level: medium
```
