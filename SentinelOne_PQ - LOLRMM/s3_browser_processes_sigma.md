```sql
// Translated content (automatically translated on 04-10-2025 00:44:25):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path="*\\s3browser*.exe")
```


# Original Sigma Rule:
```yaml
title: Potential S3 Browser RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - '*\s3browser*.exe'
  condition: selection
id: 578521d9-c5ea-4acb-848b-137796c5bd3a
status: experimental
description: Detects potential processes activity of S3 Browser RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of S3 Browser
level: medium
```
