```sql
// Translated content (automatically translated on 02-08-2025 00:55:07):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "\AmazonCloudDrive.exe")
```


# Original Sigma Rule:
```yaml
title: Potential Amazon (Cloud) Drive RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - '*\AmazonCloudDrive.exe'
  condition: selection
id: 786546bb-4108-481e-9309-a498b49009bf
status: experimental
description: Detects potential processes activity of Amazon (Cloud) Drive RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Amazon (Cloud) Drive
level: medium
```
