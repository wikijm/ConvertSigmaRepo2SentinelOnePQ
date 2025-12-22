```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path="*parallelsaccess-*.exe" or src.process.image.path contains "TSClient.exe" or src.process.image.path contains "prl_deskctl_agent.exe" or src.process.image.path contains "prl_deskctl_wizard.exe" or src.process.image.path contains "prl_pm_service.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential Parallels Access RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - parallelsaccess-*.exe
    - TSClient.exe
    - prl_deskctl_agent.exe
    - prl_deskctl_wizard.exe
    - prl_pm_service.exe
  condition: selection
id: 4ec659d8-483d-42a2-b935-21c32bf4e37e
status: experimental
description: Detects potential processes activity of Parallels Access RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Parallels Access
level: medium
```
