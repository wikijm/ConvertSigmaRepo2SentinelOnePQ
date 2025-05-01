```sql
// Translated content (automatically translated on 01-05-2025 00:56:09):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path="*\CloudBuckIt*.exe")
```


# Original Sigma Rule:
```yaml
title: Potential CloudBuckIt RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - '*\CloudBuckIt*.exe'
  condition: selection
id: eaba647a-e577-414d-bdd5-16062dc9682c
status: experimental
description: Detects potential processes activity of CloudBuckIt RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of CloudBuckIt
level: medium
```
