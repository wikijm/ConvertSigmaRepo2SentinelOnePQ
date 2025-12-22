```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "\\StorageExplorer.exe")
```


# Original Sigma Rule:
```yaml
title: Potential Azure Storage Explorer RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - '*\StorageExplorer.exe'
  condition: selection
id: 5a756379-897d-47ec-b00a-5fa73eaf4988
status: experimental
description: Detects potential processes activity of Azure Storage Explorer RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Azure Storage Explorer
level: medium
```
