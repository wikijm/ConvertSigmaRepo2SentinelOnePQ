```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path="*AgentSetup-*.exe")
```


# Original Sigma Rule:
```yaml
title: Potential Naverisk RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - AgentSetup-*.exe
  condition: selection
id: 937c6b2e-0b0f-4ebb-a5a5-6dbcf9e7bde2
status: experimental
description: Detects potential processes activity of Naverisk RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Naverisk
level: medium
```
