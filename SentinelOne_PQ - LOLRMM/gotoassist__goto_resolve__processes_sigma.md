```sql
// Translated content (automatically translated on 06-09-2026 01:47:37):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\\GoToResolveExternalModuleHandler.exe" or src.process.image.path contains "\\GoToResolveFileManager.exe" or src.process.image.path contains "\\GoToResolveLoggerProcess.exe" or src.process.image.path contains "\\GoToResolveNetworkChecker.exe" or src.process.image.path contains "\\GoToResolveProcessChecker.exe" or src.process.image.path contains "\\GoToResolveQuickView.exe" or src.process.image.path contains "\\GoToResolveRegistryEditor.exe" or src.process.image.path contains "\\GoToResolveRemoteControl.exe" or src.process.image.path contains "\\GoToResolveService.exe" or src.process.image.path contains "\\GoToResolveServiceManager.exe" or src.process.image.path contains "\\GoToResolveTerminal.exe" or src.process.image.path contains "\\GoToResolveTools32.exe" or src.process.image.path contains "\\GoToResolveTools64.exe" or src.process.image.path contains "\\GoToResolveUi.exe" or src.process.image.path contains "\\GoToResolveUnattended.exe" or src.process.image.path contains "\\GoToResolveUnattendedRemover.exe" or src.process.image.path contains "\\GoToResolveUnattendedUi.exe") or (tgt.process.image.path contains "\\GoToResolveExternalModuleHandler.exe" or tgt.process.image.path contains "\\GoToResolveFileManager.exe" or tgt.process.image.path contains "\\GoToResolveLoggerProcess.exe" or tgt.process.image.path contains "\\GoToResolveNetworkChecker.exe" or tgt.process.image.path contains "\\GoToResolveProcessChecker.exe" or tgt.process.image.path contains "\\GoToResolveQuickView.exe" or tgt.process.image.path contains "\\GoToResolveRegistryEditor.exe" or tgt.process.image.path contains "\\GoToResolveRemoteControl.exe" or tgt.process.image.path contains "\\GoToResolveService.exe" or tgt.process.image.path contains "\\GoToResolveServiceManager.exe" or tgt.process.image.path contains "\\GoToResolveTerminal.exe" or tgt.process.image.path contains "\\GoToResolveTools32.exe" or tgt.process.image.path contains "\\GoToResolveTools64.exe" or tgt.process.image.path contains "\\GoToResolveUi.exe" or tgt.process.image.path contains "\\GoToResolveUnattended.exe" or tgt.process.image.path contains "\\GoToResolveUnattendedRemover.exe" or tgt.process.image.path contains "\\GoToResolveUnattendedUi.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential GoToAssist (GoTo Resolve) RMM Tool Process Activity
id: 4e0ef8de-247d-5a7c-ac54-5d48051ad3fc
status: experimental
description: |
    Detects potential processes activity of GoToAssist (GoTo Resolve) RMM tool
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
            - '\\GoToResolveExternalModuleHandler.exe'
            - '\\GoToResolveFileManager.exe'
            - '\\GoToResolveLoggerProcess.exe'
            - '\\GoToResolveNetworkChecker.exe'
            - '\\GoToResolveProcessChecker.exe'
            - '\\GoToResolveQuickView.exe'
            - '\\GoToResolveRegistryEditor.exe'
            - '\\GoToResolveRemoteControl.exe'
            - '\\GoToResolveService.exe'
            - '\\GoToResolveServiceManager.exe'
            - '\\GoToResolveTerminal.exe'
            - '\\GoToResolveTools32.exe'
            - '\\GoToResolveTools64.exe'
            - '\\GoToResolveUi.exe'
            - '\\GoToResolveUnattended.exe'
            - '\\GoToResolveUnattendedRemover.exe'
            - '\\GoToResolveUnattendedUi.exe'
    selection_image:
        Image|endswith:
            - '\\GoToResolveExternalModuleHandler.exe'
            - '\\GoToResolveFileManager.exe'
            - '\\GoToResolveLoggerProcess.exe'
            - '\\GoToResolveNetworkChecker.exe'
            - '\\GoToResolveProcessChecker.exe'
            - '\\GoToResolveQuickView.exe'
            - '\\GoToResolveRegistryEditor.exe'
            - '\\GoToResolveRemoteControl.exe'
            - '\\GoToResolveService.exe'
            - '\\GoToResolveServiceManager.exe'
            - '\\GoToResolveTerminal.exe'
            - '\\GoToResolveTools32.exe'
            - '\\GoToResolveTools64.exe'
            - '\\GoToResolveUi.exe'
            - '\\GoToResolveUnattended.exe'
            - '\\GoToResolveUnattendedRemover.exe'
            - '\\GoToResolveUnattendedUi.exe'
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of GoToAssist (GoTo Resolve)
level: medium
```
