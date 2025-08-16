```sql
// Translated content (automatically translated on 16-08-2025 01:38:29):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "\\cloudmounter.exe")
```


# Original Sigma Rule:
```yaml
title: Potential CloudMounter RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - '*\cloudmounter.exe'
  condition: selection
id: 75a0db57-84e2-481d-852a-c181fe747964
status: experimental
description: Detects potential processes activity of CloudMounter RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of CloudMounter
level: medium
```
