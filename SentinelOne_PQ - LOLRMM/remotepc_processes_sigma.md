```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "remotepcservice.exe" or src.process.image.path contains "RemotePC.exe" or src.process.image.path contains "remotepchost.exe" or src.process.image.path contains "rpcsuite.exe" or src.process.image.path contains "RemotePCService.exe" or src.process.image.path contains "RemotePCService.exe") or (tgt.process.image.path contains "remotepcservice.exe" or tgt.process.image.path contains "RemotePC.exe" or tgt.process.image.path contains "remotepchost.exe" or tgt.process.image.path contains "rpcsuite.exe" or tgt.process.image.path contains "RemotePCService.exe" or tgt.process.image.path contains "RemotePCService.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential RemotePC RMM Tool Process Activity
id: 5b7c22f4-9bd6-4ec1-8624-6a0798fee565
status: experimental
description: |
    Detects potential processes activity of RemotePC RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2025-12-01
tags:
    - attack.execution
    - attack.t1219
logsource:
    product: windows
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith:
            - remotepcservice.exe
            - RemotePC.exe
            - remotepchost.exe
            - rpcsuite.exe
            - RemotePCService.exe
            - RemotePCService.exe
    selection_image:
        Image|endswith:
            - remotepcservice.exe
            - RemotePC.exe
            - remotepchost.exe
            - rpcsuite.exe
            - RemotePCService.exe
            - RemotePCService.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of RemotePC
level: medium
```
