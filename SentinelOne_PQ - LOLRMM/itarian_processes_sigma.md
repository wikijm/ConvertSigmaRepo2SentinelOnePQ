```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "ITSMAgent.exe" or src.process.image.path contains "RViewer.exe" or src.process.image.path contains "ItsmRsp.exe" or src.process.image.path contains "RAccess.exe" or src.process.image.path contains "RmmService.exe" or src.process.image.path contains "ITarianRemoteAccessSetup.exe" or src.process.image.path contains "RDesktop.exe" or src.process.image.path contains "ComodoRemoteControl.exe" or src.process.image.path contains "ITSMService.exe" or src.process.image.path contains "RHost.exe") or (tgt.process.image.path contains "ITSMAgent.exe" or tgt.process.image.path contains "RViewer.exe" or tgt.process.image.path contains "ItsmRsp.exe" or tgt.process.image.path contains "RAccess.exe" or tgt.process.image.path contains "RmmService.exe" or tgt.process.image.path contains "ITarianRemoteAccessSetup.exe" or tgt.process.image.path contains "RDesktop.exe" or tgt.process.image.path contains "ComodoRemoteControl.exe" or tgt.process.image.path contains "ITSMService.exe" or tgt.process.image.path contains "RHost.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Itarian RMM Tool Process Activity
id: c3e4f4a8-5086-404b-a03c-4e679e12125d
status: experimental
description: |
    Detects potential processes activity of Itarian RMM tool
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
            - ITSMAgent.exe
            - RViewer.exe
            - ItsmRsp.exe
            - RAccess.exe
            - RmmService.exe
            - ITarianRemoteAccessSetup.exe
            - RDesktop.exe
            - ComodoRemoteControl.exe
            - ITSMService.exe
            - RHost.exe
    selection_image:
        Image|endswith:
            - ITSMAgent.exe
            - RViewer.exe
            - ItsmRsp.exe
            - RAccess.exe
            - RmmService.exe
            - ITarianRemoteAccessSetup.exe
            - RDesktop.exe
            - ComodoRemoteControl.exe
            - ITSMService.exe
            - RHost.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Itarian
level: medium
```
