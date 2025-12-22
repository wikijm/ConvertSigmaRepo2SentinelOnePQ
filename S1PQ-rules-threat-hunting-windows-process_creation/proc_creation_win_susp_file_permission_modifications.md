```sql
// Translated content (automatically translated on 22-12-2025 00:55:34):
event.type="Process Creation" and (endpoint.os="windows" and ((((tgt.process.image.path contains "\\cacls.exe" or tgt.process.image.path contains "\\icacls.exe" or tgt.process.image.path contains "\\net.exe" or tgt.process.image.path contains "\\net1.exe") and (tgt.process.cmdline contains "/grant" or tgt.process.cmdline contains "/setowner" or tgt.process.cmdline contains "/inheritance:r")) or (tgt.process.image.path contains "\\attrib.exe" and tgt.process.cmdline contains "-r") or tgt.process.image.path contains "\\takeown.exe") and (not (tgt.process.cmdline contains "ICACLS C:\\ProgramData\\dynatrace\\gateway\\config\\connectivity.history /reset" or (tgt.process.cmdline contains "ICACLS C:\\ProgramData\\dynatrace\\gateway\\config\\config.properties /grant :r " and tgt.process.cmdline contains "S-1-5-19:F") or (tgt.process.cmdline contains "\\AppData\\Local\\Programs\\Microsoft VS Code" or tgt.process.cmdline contains ":\\Program Files\\Microsoft VS Code") or (tgt.process.cmdline contains ":\\Program Files (x86)\\Avira" or tgt.process.cmdline contains ":\\Program Files\\Avira")))))
```


# Original Sigma Rule:
```yaml
title: File or Folder Permissions Modifications
id: 37ae075c-271b-459b-8d7b-55ad5f993dd8
status: test
description: Detects a file or folder's permissions being modified or tampered with.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1222.001/T1222.001.md
    - https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh750728(v=ws.11)
    - https://github.com/swagkarna/Defeat-Defender-V1.2.0/tree/ae4059c4276da6f6303b8f53cdff085ecae88a91
author: Jakob Weinzettl, oscd.community, Nasreddine Bencherchali (Nextron Systems)
date: 2019-10-23
modified: 2023-11-21
tags:
    - attack.defense-evasion
    - attack.t1222.001
    - detection.threat-hunting
logsource:
    category: process_creation
    product: windows
detection:
    selection_1:
        Image|endswith:
            - '\cacls.exe'
            - '\icacls.exe'
            - '\net.exe' # "grant" Option available when used with "net share"
            - '\net1.exe' # "grant" Option available when used with "net share"
        CommandLine|contains:
            - '/grant'
            - '/setowner'
            - '/inheritance:r' # Remove all inherited ACEs
    selection_2:
        Image|endswith: '\attrib.exe'
        CommandLine|contains: '-r'
    selection_3:
        Image|endswith: '\takeown.exe' # If this generates FP in your environment. Comment it out or add more suspicious flags and locations
    filter_optional_dynatrace_1:
        CommandLine|endswith: 'ICACLS C:\ProgramData\dynatrace\gateway\config\connectivity.history /reset'
    filter_optional_dynatrace_2:
        CommandLine|contains|all:
            - 'ICACLS C:\ProgramData\dynatrace\gateway\config\config.properties /grant :r '
            - 'S-1-5-19:F'
    filter_optional_vscode:
        CommandLine|contains:
            - '\AppData\Local\Programs\Microsoft VS Code'
            - ':\Program Files\Microsoft VS Code'
    filter_optional_avira:
        CommandLine|contains:
            - ':\Program Files (x86)\Avira'
            - ':\Program Files\Avira'
    condition: 1 of selection_* and not 1 of filter_optional_*
falsepositives:
    - Users interacting with the files on their own (unlikely unless privileged users).
    - Dynatrace app
level: medium
```
