```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\\cmd.exe" and src.process.cmdline contains ".bat") and ((tgt.process.image.path contains "\\xcopy.exe" and (tgt.process.cmdline contains "powershell.exe" and tgt.process.cmdline contains ".bat.exe")) or (tgt.process.image.path contains "\\xcopy.exe" and (tgt.process.cmdline contains "pwsh.exe" and tgt.process.cmdline contains ".bat.exe")) or (tgt.process.image.path contains "\\attrib.exe" and (tgt.process.cmdline contains "+s" and tgt.process.cmdline contains "+h" and tgt.process.cmdline contains ".bat.exe")))))
```


# Original Sigma Rule:
```yaml
title: HackTool - Jlaive In-Memory Assembly Execution
id: 0a99eb3e-1617-41bd-b095-13dc767f3def
status: test
description: Detects the use of Jlaive to execute assemblies in a copied PowerShell
references:
    - https://jstnk9.github.io/jstnk9/research/Jlaive-Antivirus-Evasion-Tool
    - https://web.archive.org/web/20220514073704/https://github.com/ch2sh/Jlaive
author: Jose Luis Sanchez Martinez (@Joseliyo_Jstnk)
date: 2022-05-24
modified: 2023-02-22
tags:
    - attack.execution
    - attack.t1059.003
logsource:
    product: windows
    category: process_creation
detection:
    parent_selection:
        ParentImage|endswith: '\cmd.exe'
        ParentCommandLine|endswith: '.bat'
    selection1:
        Image|endswith: '\xcopy.exe'
        CommandLine|contains|all:
            - 'powershell.exe'
            - '.bat.exe'
    selection2:
        Image|endswith: '\xcopy.exe'
        CommandLine|contains|all:
            - 'pwsh.exe'
            - '.bat.exe'
    selection3:
        Image|endswith: '\attrib.exe'
        CommandLine|contains|all:
            - '+s'
            - '+h'
            - '.bat.exe'
    condition: parent_selection and (1 of selection*)
falsepositives:
    - Unknown
level: medium
```
