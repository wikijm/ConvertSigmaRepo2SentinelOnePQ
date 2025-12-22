```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "ltsvc.exe" or src.process.image.path contains "ltsvcmon.exe" or src.process.image.path contains "lttray.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Connectwise Automate (LabTech) RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - ltsvc.exe
    - ltsvcmon.exe
    - lttray.exe
  condition: selection
id: 3fc5c412-a53a-47ae-b2cc-e140e32a22ce
status: experimental
description: Detects potential processes activity of Connectwise Automate (LabTech)
  RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Connectwise Automate (LabTech)
level: medium
```
