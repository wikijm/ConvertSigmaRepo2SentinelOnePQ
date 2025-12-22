```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\\wscript.exe" or src.process.image.path contains "\\cscript.exe") and (tgt.process.image.path contains "\\rundll32.exe" or ((tgt.process.image.path contains "\\cmd.exe" or tgt.process.image.path contains "\\powershell.exe" or tgt.process.image.path contains "\\pwsh.exe") and ((tgt.process.cmdline contains "mshta" and tgt.process.cmdline contains "http") or (tgt.process.cmdline contains "rundll32" or tgt.process.cmdline contains "regsvr32" or tgt.process.cmdline contains "msiexec")))) and (not (tgt.process.image.path contains "\\rundll32.exe" and (tgt.process.cmdline contains "UpdatePerUserSystemParameters" or tgt.process.cmdline contains "PrintUIEntry" or tgt.process.cmdline contains "ClearMyTracksByProcess")))))
```


# Original Sigma Rule:
```yaml
title: Cscript/Wscript Potentially Suspicious Child Process
id: b6676963-0353-4f88-90f5-36c20d443c6a
status: test
description: |
    Detects potentially suspicious child processes of Wscript/Cscript. These include processes such as rundll32 with uncommon exports or PowerShell spawning rundll32 or regsvr32.
    Malware such as Pikabot and Qakbot were seen using similar techniques as well as many others.
references:
    - Internal Research
    - https://github.com/pr0xylife/Pikabot/blob/fc58126127adf0f65e78f4eec59675523f48f086/Pikabot_30.10.2023.txt
    - https://github.com/pr0xylife/Pikabot/blob/fc58126127adf0f65e78f4eec59675523f48f086/Pikabot_22.12.2023.txt
author: Nasreddine Bencherchali (Nextron Systems), Alejandro Houspanossian ('@lekz86')
date: 2023-05-15
modified: 2024-01-02
tags:
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith:
            - '\wscript.exe'
            - '\cscript.exe'
    selection_cli_script_main:
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
    # Note: Add other combinations that are suspicious
    selection_cli_script_option_mshta:
        CommandLine|contains|all:
            - 'mshta'
            - 'http'
    selection_cli_script_option_other:
        CommandLine|contains:
            - 'rundll32'
            - 'regsvr32'
            - 'msiexec'
    selection_cli_standalone:
        Image|endswith: '\rundll32.exe'
    filter_main_rundll32_known_exports:
        Image|endswith: '\rundll32.exe'
        CommandLine|contains:
            - 'UpdatePerUserSystemParameters'
            - 'PrintUIEntry'
            - 'ClearMyTracksByProcess'
    condition: selection_parent and ( selection_cli_standalone or (selection_cli_script_main and 1 of selection_cli_script_option_*) ) and not 1 of filter_main_*
falsepositives:
    - Some false positives might occur with admin or third party software scripts. Investigate and apply additional filters accordingly.
level: medium
```
