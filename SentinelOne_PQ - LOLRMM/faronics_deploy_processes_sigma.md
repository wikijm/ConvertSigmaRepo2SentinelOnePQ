```sql
// Translated content (automatically translated on 09-09-2026 02:01:10):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\\FaronicsDeployAgent.exe" or src.process.image.path contains "\\FWAService.exe" or src.process.image.path contains "\\FWA_UI_Agent.exe" or src.process.image.path contains "\\FRCServer.exe" or src.process.image.path contains "\\FaronicsSA.exe" or src.process.image.path contains "\\FSSInstaller.exe" or src.process.image.path contains "\\ModulesUpgradeMgr.exe" or src.process.image.path contains "\\NotificationHelper.exe" or src.process.image.path contains "\\UserNotificationHelper.exe" or src.process.image.path contains "\\MigrationHelper_32.exe" or src.process.image.path contains "\\MigrationHelper_64.exe" or src.process.image.path="*\\FWAWebInstaller_*.exe" or src.process.image.path contains "\\CloudWksInstall.exe") or (tgt.process.image.path contains "\\FaronicsDeployAgent.exe" or tgt.process.image.path contains "\\FWAService.exe" or tgt.process.image.path contains "\\FWA_UI_Agent.exe" or tgt.process.image.path contains "\\FRCServer.exe" or tgt.process.image.path contains "\\FaronicsSA.exe" or tgt.process.image.path contains "\\FSSInstaller.exe" or tgt.process.image.path contains "\\ModulesUpgradeMgr.exe" or tgt.process.image.path contains "\\NotificationHelper.exe" or tgt.process.image.path contains "\\UserNotificationHelper.exe" or tgt.process.image.path contains "\\MigrationHelper_32.exe" or tgt.process.image.path contains "\\MigrationHelper_64.exe" or tgt.process.image.path="*\\FWAWebInstaller_*.exe" or tgt.process.image.path contains "\\CloudWksInstall.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Faronics Deploy RMM Tool Process Activity
id: d827e66e-2b69-5cc7-9caa-1dcc00bda540
status: experimental
description: |
    Detects potential processes activity of Faronics Deploy RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-05-18
modified: 2026-09-02
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith:
            - '\\FaronicsDeployAgent.exe'
            - '\\FWAService.exe'
            - '\\FWA_UI_Agent.exe'
            - '\\FRCServer.exe'
            - '\\FaronicsSA.exe'
            - '\\FSSInstaller.exe'
            - '\\ModulesUpgradeMgr.exe'
            - '\\NotificationHelper.exe'
            - '\\UserNotificationHelper.exe'
            - '\\MigrationHelper_32.exe'
            - '\\MigrationHelper_64.exe'
            - '\\FWAWebInstaller_*.exe'
            - '\\CloudWksInstall.exe'
    selection_image:
        Image|endswith:
            - '\\FaronicsDeployAgent.exe'
            - '\\FWAService.exe'
            - '\\FWA_UI_Agent.exe'
            - '\\FRCServer.exe'
            - '\\FaronicsSA.exe'
            - '\\FSSInstaller.exe'
            - '\\ModulesUpgradeMgr.exe'
            - '\\NotificationHelper.exe'
            - '\\UserNotificationHelper.exe'
            - '\\MigrationHelper_32.exe'
            - '\\MigrationHelper_64.exe'
            - '\\FWAWebInstaller_*.exe'
            - '\\CloudWksInstall.exe'
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Faronics Deploy
level: medium
```
