```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "nhostsvc.exe" or src.process.image.path contains "nhstw32.exe" or src.process.image.path contains "ngstw32.exe" or src.process.image.path contains "Netop Ondemand.exe" or src.process.image.path contains "nldrw32.exe" or src.process.image.path contains "rmserverconsolemediator.exe" or src.process.image.path contains "ImperoInit.exe" or src.process.image.path="*Connect.Backdrop.cloud*.exe" or src.process.image.path contains "ImperoClientSVC.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Netop Remote Control (Impero Connect) RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - nhostsvc.exe
    - nhstw32.exe
    - ngstw32.exe
    - Netop Ondemand.exe
    - nldrw32.exe
    - rmserverconsolemediator.exe
    - ImperoInit.exe
    - Connect.Backdrop.cloud*.exe
    - ImperoClientSVC.exe
  condition: selection
id: 4c7a92e7-bc61-4a3f-aeed-5dfe56fae30a
status: experimental
description: Detects potential processes activity of Netop Remote Control (Impero
  Connect) RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Netop Remote Control (Impero Connect)
level: medium
```
