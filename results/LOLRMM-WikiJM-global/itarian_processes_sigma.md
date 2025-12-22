```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "ITSMAgent.exe" or src.process.image.path contains "RViewer.exe" or src.process.image.path contains "ItsmRsp.exe" or src.process.image.path contains "RAccess.exe" or src.process.image.path contains "RmmService.exe" or src.process.image.path contains "ITarianRemoteAccessSetup.exe" or src.process.image.path contains "RDesktop.exe" or src.process.image.path contains "ComodoRemoteControl.exe" or src.process.image.path contains "ITSMService.exe" or src.process.image.path contains "RHost.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Itarian RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
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
  condition: selection
id: 57c6e0df-6077-4f29-b48d-2999d628c549
status: experimental
description: Detects potential processes activity of Itarian RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Itarian
level: medium
```
