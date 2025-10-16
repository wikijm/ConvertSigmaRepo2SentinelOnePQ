```sql
// Translated content (automatically translated on 16-10-2025 00:49:45):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "\\BvSshClient-Inst.exe")
```


# Original Sigma Rule:
```yaml
title: Potential Bitvise SSH Client RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - '*\BvSshClient-Inst.exe'
  condition: selection
id: 32fcae3a-a465-4a26-95f6-b18f3018c631
status: experimental
description: Detects potential processes activity of Bitvise SSH Client RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Bitvise SSH Client
level: medium
```
