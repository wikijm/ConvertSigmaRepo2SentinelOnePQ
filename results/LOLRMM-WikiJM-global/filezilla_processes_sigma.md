```sql
// Translated content (automatically translated on 29-01-2026 02:04:22):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "\\FileZilla.exe")
```


# Original Sigma Rule:
```yaml
title: Potential FileZilla RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - '*\FileZilla.exe'
  condition: selection
id: 214b6209-b165-4b2a-943e-2bae48ad5664
status: experimental
description: Detects potential processes activity of FileZilla RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of FileZilla
level: medium
```
