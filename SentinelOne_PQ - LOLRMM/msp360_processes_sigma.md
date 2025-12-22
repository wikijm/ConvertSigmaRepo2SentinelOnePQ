```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "Online Backup.exe" or src.process.image.path contains "CBBackupPlan.exe" or src.process.image.path contains "Cloud.Backup.Scheduler.exe" or src.process.image.path contains "Cloud.Backup.RM.Service.exe" or src.process.image.path contains "cbb.exe" or src.process.image.path contains "CloudRaService.exe" or src.process.image.path contains "CloudRaSd.exe" or src.process.image.path contains "CloudRaCmd.exe" or src.process.image.path contains "CloudRaUtilities.exe" or src.process.image.path contains "Remote Desktop.exe" or src.process.image.path contains "Connect.exe") or (tgt.process.image.path contains "Online Backup.exe" or tgt.process.image.path contains "CBBackupPlan.exe" or tgt.process.image.path contains "Cloud.Backup.Scheduler.exe" or tgt.process.image.path contains "Cloud.Backup.RM.Service.exe" or tgt.process.image.path contains "cbb.exe" or tgt.process.image.path contains "CloudRaService.exe" or tgt.process.image.path contains "CloudRaSd.exe" or tgt.process.image.path contains "CloudRaCmd.exe" or tgt.process.image.path contains "CloudRaUtilities.exe" or tgt.process.image.path contains "Remote Desktop.exe" or tgt.process.image.path contains "Connect.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential MSP360 RMM Tool Process Activity
id: 14954416-e9cf-4b77-abf3-fc08526a7319
status: experimental
description: |
    Detects potential processes activity of MSP360 RMM tool
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
    selection_image:
        Image|endswith:
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
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of MSP360
level: medium
```
