```sql
// Translated content (automatically translated on 29-08-2025 01:25:50):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "C:\\AlpemixService.exe")
```


# Original Sigma Rule:
```yaml
title: Potential Alpemix RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - C:\AlpemixService.exe
  condition: selection
id: 36f4abfb-41ad-41eb-a463-d928daef3de3
status: experimental
description: Detects potential processes activity of Alpemix RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Alpemix
level: medium
```
