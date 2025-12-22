```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "remotepcservice.exe" or src.process.image.path contains "RemotePC.exe" or src.process.image.path contains "remotepchost.exe" or src.process.image.path contains "rpcsuite.exe" or src.process.image.path contains "\\RemotePCService.exe" or src.process.image.path contains "RemotePCService.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential RemotePC RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - remotepcservice.exe
    - RemotePC.exe
    - remotepchost.exe
    - rpcsuite.exe
    - '*\RemotePCService.exe'
    - RemotePCService.exe
  condition: selection
id: 5afe5393-d9b5-47e6-a332-a32ba5f07fea
status: experimental
description: Detects potential processes activity of RemotePC RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of RemotePC
level: medium
```
