```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "Online Backup.exe" or src.process.image.path contains "CBBackupPlan.exe" or src.process.image.path contains "Cloud.Backup.Scheduler.exe" or src.process.image.path contains "Cloud.Backup.RM.Service.exe" or src.process.image.path contains "cbb.exe" or src.process.image.path contains "CloudRaService.exe" or src.process.image.path contains "CloudRaSd.exe" or src.process.image.path contains "CloudRaCmd.exe" or src.process.image.path contains "CloudRaUtilities.exe" or src.process.image.path contains "Remote Desktop.exe" or src.process.image.path contains "Connect.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential MSP360 RMM Tool Process Activity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
    - Online Backup.exe
    - CBBackupPlan.exe
    - Cloud.Backup.Scheduler.exe
    - Cloud.Backup.RM.Service.exe
    - cbb.exe
    - CloudRaService.exe
    - CloudRaSd.exe
    - CloudRaCmd.exe
    - CloudRaUtilities.exe
    - Remote Desktop.exe
    - Connect.exe
  condition: selection
id: 8bb15580-456b-4f5c-87ba-895a2f5fc91a
status: experimental
description: Detects potential processes activity of MSP360 RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of MSP360
level: medium
```
