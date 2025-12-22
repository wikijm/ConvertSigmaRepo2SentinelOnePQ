```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path="*helpbeam*.exe")
```


# Original Sigma Rule:
```yaml
title: Potential HelpBeam RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - helpbeam*.exe
  condition: selection
id: a79a8449-d2a8-4d4e-9050-3e1fb530f790
status: experimental
description: Detects potential processes activity of HelpBeam RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of HelpBeam
level: medium
```
