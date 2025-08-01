```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\cmd.exe" or src.process.image.path contains "\powershell.exe" or src.process.image.path contains "\pwsh.exe") and tgt.process.image.path contains "\explorer.exe" and tgt.process.cmdline contains "shell:mycomputerfolder"))
```


# Original Sigma Rule:
```yaml
title: File Explorer Folder Opened Using Explorer Folder Shortcut Via Shell
id: c3d76afc-93df-461e-8e67-9b2bad3f2ac4
status: test
description: |
    Detects the initial execution of "cmd.exe" which spawns "explorer.exe" with the appropriate command line arguments for opening the "My Computer" folder.
author: '@Kostastsale'
references:
    - https://ss64.com/nt/shell.html
date: 2022-12-22
modified: 2024-08-23
tags:
    - attack.discovery
    - attack.t1135
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        ParentImage|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
        Image|endswith: '\explorer.exe'
        CommandLine|contains: 'shell:mycomputerfolder'
    condition: selection
falsepositives:
    - Unknown
level: high
```
