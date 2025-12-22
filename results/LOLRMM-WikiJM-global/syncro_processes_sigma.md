```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "Syncro.Installer.exe" or src.process.image.path contains "Kabuto.App.Runner.exe" or src.process.image.path contains "Syncro.Overmind.Service.exe" or src.process.image.path contains "Kabuto.Installer.exe" or src.process.image.path contains "KabutoSetup.exe" or src.process.image.path contains "Syncro.Service.exe" or src.process.image.path contains "Kabuto.Service.Runner.exe" or src.process.image.path contains "Syncro.App.Runner.exe" or src.process.image.path contains "SyncroLive.Service.exe" or src.process.image.path contains "SyncroLive.Agent.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Syncro RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - Syncro.Installer.exe
    - Kabuto.App.Runner.exe
    - Syncro.Overmind.Service.exe
    - Kabuto.Installer.exe
    - KabutoSetup.exe
    - Syncro.Service.exe
    - Kabuto.Service.Runner.exe
    - Syncro.App.Runner.exe
    - SyncroLive.Service.exe
    - SyncroLive.Agent.exe
  condition: selection
id: 1dae4fcd-efac-4f3a-8a66-9faa8db0f808
status: experimental
description: Detects potential processes activity of Syncro RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Syncro
level: medium
```
