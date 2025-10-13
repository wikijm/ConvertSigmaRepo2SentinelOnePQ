```sql
// Translated content (automatically translated on 13-10-2025 00:52:23):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "ltsvc.exe" or src.process.image.path contains "ltsvcmon.exe" or src.process.image.path contains "lttray.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential LabTech RMM (Now ConnectWise Automate) RMM Tool Process Activity
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
id: 618f0058-e014-443d-ac07-18e946dcfc4e
status: experimental
description: Detects potential processes activity of LabTech RMM (Now ConnectWise
  Automate) RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of LabTech RMM (Now ConnectWise Automate)
level: medium
```
