```sql
// Translated content (automatically translated on 22-12-2025 00:55:34):
event.type="Process Creation" and (endpoint.os="windows" and (((src.process.image.path="*\\7z*.exe" and tgt.process.cmdline="*\\AppData\\local\\temp\\7z*\\*") or (src.process.image.path contains "\\winrar.exe" and tgt.process.cmdline="*\\AppData\\local\\temp\\rar*\\*") or (src.process.image.path contains "\\explorer.exe" and (tgt.process.cmdline contains "\\AppData\\local\\temp\*.rar\\" or tgt.process.cmdline contains "\\AppData\\local\\temp\*.zip\\"))) and ((tgt.process.image.path contains "\\cscript.exe" or tgt.process.image.path contains "\\mshta.exe" or tgt.process.image.path contains "\\powershell.exe" or tgt.process.image.path contains "\\pwsh.exe" or tgt.process.image.path contains "\\wscript.exe") and (tgt.process.cmdline contains ".hta" or tgt.process.cmdline contains ".js" or tgt.process.cmdline contains ".jse" or tgt.process.cmdline contains ".ps1" or tgt.process.cmdline contains ".vbe" or tgt.process.cmdline contains ".vbs" or tgt.process.cmdline contains ".wsf" or tgt.process.cmdline contains ".wsh"))))
```


# Original Sigma Rule:
```yaml
title: Manual Execution of Script Inside of a Compressed File
id: 95724fc1-a258-4674-97db-a30351981c5a
status: test
description: |
    This is a threat-hunting query to collect information related to the interactive execution of a script from inside a compressed file (zip/rar). Windows will automatically run the script using scripting interpreters such as wscript and cscript binaries.

    From the query below, the child process is the script interpreter that will execute the script. The script extension is also a set of standard extensions that Windows OS recognizes. Selections 1-3 contain three different execution scenarios.
        1. Compressed file opened using 7zip.
        2. Compressed file opened using WinRar.
        3. Compressed file opened using native windows File Explorer capabilities.

    When the malicious script is double-clicked, it will be extracted to the respected directories as signified by the CommandLine on each of the three Selections. It will then be executed using the relevant script interpreter."
references:
    - https://app.any.run/tasks/25970bb5-f864-4e9e-9e1b-cc8ff9e6386a
    - https://app.any.run/tasks/fa99cedc-9d2f-4115-a08e-291429ce3692
author: '@kostastsale'
date: 2023-02-15
modified: 2024-08-13
tags:
    - attack.execution
    - attack.t1059
    - detection.threat-hunting
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent_7zip:
        ParentImage|endswith: '\7z*.exe'
        CommandLine|contains: '\AppData\local\temp\7z*\'
    selection_parent_winrar:
        ParentImage|endswith: '\winrar.exe'
        CommandLine|contains: '\AppData\local\temp\rar*\'
    selection_parent_explorer:
        ParentImage|endswith: '\explorer.exe'
        CommandLine|contains:
            - '\AppData\local\temp\*.rar\'
            - '\AppData\local\temp\*.zip\'
    selection_child:
        Image|endswith:
            - '\cscript.exe'
            - '\mshta.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\wscript.exe'
        CommandLine|endswith:
            - '.hta'
            - '.js'
            - '.jse'
            - '.ps1'
            - '.vbe'
            - '.vbs'
            - '.wsf'
            - '.wsh'
    condition: 1 of selection_parent_* and selection_child
falsepositives:
    - Batch files may produce a lot of noise, as many applications appear to bundle them as part of their installation process. You should baseline your environment and generate a new query excluding the noisy and expected activity. Some false positives may come up depending on your environment. All results should be investigated thoroughly before filtering out results.
level: medium
```
