```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "remote_host.exe" or src.process.image.path contains "remoting_host.exe" or src.process.image.path contains "\\remoting_host.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Chrome Remote Desktop RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - remote_host.exe
    - remoting_host.exe
    - '*\remoting_host.exe'
  condition: selection
id: 9ba8e1a9-1a5f-4297-bc82-712f5427355a
status: experimental
description: Detects potential processes activity of Chrome Remote Desktop RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Chrome Remote Desktop
level: medium
```
