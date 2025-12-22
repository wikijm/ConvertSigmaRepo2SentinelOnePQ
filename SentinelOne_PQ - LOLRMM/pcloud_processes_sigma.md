```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "\\pCloud.exe")
```


# Original Sigma Rule:
```yaml
title: Potential pCloud RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - '*\pCloud.exe'
  condition: selection
id: 3362dfd5-217c-4d6f-afe8-c2a4d25e5e56
status: experimental
description: Detects potential processes activity of pCloud RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of pCloud
level: medium
```
