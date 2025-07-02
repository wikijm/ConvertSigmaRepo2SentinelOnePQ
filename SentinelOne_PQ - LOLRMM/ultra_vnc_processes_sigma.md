```sql
// Translated content (automatically translated on 02-07-2025 00:54:09):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\UVNC_Launch.exe" or src.process.image.path contains "\winvnc.exe" or src.process.image.path contains "\vncviewer.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Ultra VNC RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - '*\UVNC_Launch.exe'
    - '*\winvnc.exe'
    - '*\vncviewer.exe'
  condition: selection
id: dd1b2f4a-644e-4794-b261-917ac7e3046b
status: experimental
description: Detects potential processes activity of Ultra VNC RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Ultra VNC
level: medium
```
