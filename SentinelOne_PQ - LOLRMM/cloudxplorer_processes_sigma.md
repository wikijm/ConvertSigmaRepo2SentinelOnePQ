```sql
// Translated content (automatically translated on 18-08-2025 00:57:56):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path="*\\clumsyleaf.cloudxplorer*.exe")
```


# Original Sigma Rule:
```yaml
title: Potential CloudXplorer RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - '*\clumsyleaf.cloudxplorer*.exe'
  condition: selection
id: ac3686dd-66b2-4b2a-94e0-c26a2487bd9a
status: experimental
description: Detects potential processes activity of CloudXplorer RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of CloudXplorer
level: medium
```
