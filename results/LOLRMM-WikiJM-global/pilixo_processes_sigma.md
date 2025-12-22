```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "rdp.exe" or src.process.image.path="*Pilixo_Installer*.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Pilixo RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - rdp.exe
    - Pilixo_Installer*.exe
  condition: selection
id: c2649604-3b30-47b0-ae8b-aaea69ccdf9b
status: experimental
description: Detects potential processes activity of Pilixo RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Pilixo
level: medium
```
