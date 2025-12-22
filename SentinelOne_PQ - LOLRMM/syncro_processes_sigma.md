```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "Syncro.Installer.exe" or src.process.image.path contains "Kabuto.App.Runner.exe" or src.process.image.path contains "Syncro.Overmind.Service.exe" or src.process.image.path contains "Kabuto.Installer.exe" or src.process.image.path contains "KabutoSetup.exe" or src.process.image.path contains "Syncro.Service.exe" or src.process.image.path contains "Kabuto.Service.Runner.exe" or src.process.image.path contains "Syncro.App.Runner.exe" or src.process.image.path contains "SyncroLive.Service.exe" or src.process.image.path contains "SyncroLive.Agent.exe") or (tgt.process.image.path contains "Syncro.Installer.exe" or tgt.process.image.path contains "Kabuto.App.Runner.exe" or tgt.process.image.path contains "Syncro.Overmind.Service.exe" or tgt.process.image.path contains "Kabuto.Installer.exe" or tgt.process.image.path contains "KabutoSetup.exe" or tgt.process.image.path contains "Syncro.Service.exe" or tgt.process.image.path contains "Kabuto.Service.Runner.exe" or tgt.process.image.path contains "Syncro.App.Runner.exe" or tgt.process.image.path contains "SyncroLive.Service.exe" or tgt.process.image.path contains "SyncroLive.Agent.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Syncro RMM Tool Process Activity
id: cf4cd05a-5d37-4008-8783-ca04c7bc488d
status: experimental
description: |
    Detects potential processes activity of Syncro RMM tool
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
    selection_image:
        Image|endswith:
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
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Syncro
level: medium
```
