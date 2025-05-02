```sql
// Translated content (automatically translated on 02-05-2025 01:36:20):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "nhostsvc.exe" or src.process.image.path contains "nhstw32.exe" or src.process.image.path contains "nldrw32.exe" or src.process.image.path contains "rmserverconsolemediator.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Netop Remote Control (aka Impero Connect) RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - nhostsvc.exe
    - nhstw32.exe
    - nldrw32.exe
    - rmserverconsolemediator.exe
  condition: selection
id: 3a4303d5-7d7f-4ea2-9d7e-f218c5971713
status: experimental
description: Detects potential processes activity of Netop Remote Control (aka Impero
  Connect) RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Netop Remote Control (aka Impero Connect)
level: medium
```
