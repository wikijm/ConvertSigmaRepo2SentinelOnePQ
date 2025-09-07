```sql
// Translated content (automatically translated on 07-09-2025 01:36:04):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "ManualLauncher.exe")
```


# Original Sigma Rule:
```yaml
title: Potential Any Support RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - ManualLauncher.exe
  condition: selection
id: 9a46a911-07de-4a3e-9bd9-4a47a0e015c4
status: experimental
description: Detects potential processes activity of Any Support RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Any Support
level: medium
```
