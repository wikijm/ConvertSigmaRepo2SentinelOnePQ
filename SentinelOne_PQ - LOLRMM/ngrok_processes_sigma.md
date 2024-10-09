```sql
// Translated content (automatically translated on 08-10-2024 15:38:03):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "ngrok.exe")
```


# Original Sigma Rule:
```yaml
title: Potential ngrok RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - ngrok.exe
  condition: selection
id: 5c6a492b-4f87-4f2f-8f1d-95b1c7c16ef1
status: experimental
description: Detects potential processes activity of ngrok RMM tool
author: LOLRMM Project
date: 2024-08-07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of ngrok
level: medium
```