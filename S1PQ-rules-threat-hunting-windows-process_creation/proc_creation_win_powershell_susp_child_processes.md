```sql
// Translated content (automatically translated on 02-08-2025 00:52:11):
event.type="Process Creation" and (endpoint.os="windows" and (((src.process.image.path contains "\powershell_ise.exe" or src.process.image.path contains "\powershell.exe" or src.process.image.path contains "\pwsh.exe") and (tgt.process.image.path contains "\bash.exe" or tgt.process.image.path contains "\bitsadmin.exe" or tgt.process.image.path contains "\certutil.exe" or tgt.process.image.path contains "\cscript.exe" or tgt.process.image.path contains "\forfiles.exe" or tgt.process.image.path contains "\hh.exe" or tgt.process.image.path contains "\mshta.exe" or tgt.process.image.path contains "\regsvr32.exe" or tgt.process.image.path contains "\rundll32.exe" or tgt.process.image.path contains "\schtasks.exe" or tgt.process.image.path contains "\scrcons.exe" or tgt.process.image.path contains "\scriptrunner.exe" or tgt.process.image.path contains "\sh.exe" or tgt.process.image.path contains "\wmic.exe" or tgt.process.image.path contains "\wscript.exe")) and (not ((tgt.process.image.path contains "\certutil.exe" and tgt.process.cmdline contains "-verifystore ") or (tgt.process.image.path contains "\wmic.exe" and (tgt.process.cmdline contains "qfe list" or tgt.process.cmdline contains "diskdrive " or tgt.process.cmdline contains "csproduct " or tgt.process.cmdline contains "computersystem " or tgt.process.cmdline contains " os " or tgt.process.cmdline contains "")))) and (not (src.process.cmdline contains "\Program Files\Amazon\WorkspacesConfig\Scripts\" and tgt.process.cmdline contains "\Program Files\Amazon\WorkspacesConfig\Scripts\"))))
```


# Original Sigma Rule:
```yaml
title: Potentially Suspicious PowerShell Child Processes
id: e4b6d2a7-d8a4-4f19-acbd-943c16d90647
status: test
description: |
    Detects potentially suspicious child processes spawned by PowerShell.
    Use this rule to hunt for potential anomalies initiating from PowerShell scripts and commands.
references:
    - https://twitter.com/ankit_anubhav/status/1518835408502620162
author: Florian Roth (Nextron Systems), Tim Shelton
date: 2022-04-26
modified: 2024-07-16
tags:
    - attack.execution
    - attack.t1059.001
    - detection.threat-hunting
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith:
            - '\powershell_ise.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
        Image|endswith:
            - '\bash.exe'
            - '\bitsadmin.exe'
            - '\certutil.exe'
            - '\cscript.exe'
            - '\forfiles.exe'
            - '\hh.exe'
            - '\mshta.exe'
            - '\regsvr32.exe'
            - '\rundll32.exe'
            - '\schtasks.exe'
            - '\scrcons.exe'
            - '\scriptrunner.exe'
            - '\sh.exe'
            - '\wmic.exe'
            - '\wscript.exe'
    filter_optional_amazon:
        ParentCommandLine|contains: '\Program Files\Amazon\WorkspacesConfig\Scripts\'  # AWS Workspaces
        CommandLine|contains: '\Program Files\Amazon\WorkspacesConfig\Scripts\'  # AWS Workspaces
    filter_main_certutil_verify_store:
        Image|endswith: '\certutil.exe'
        CommandLine|contains: '-verifystore '
    filter_main_wmic:
        Image|endswith: '\wmic.exe'
        CommandLine|contains:
            - 'qfe list'
            - 'diskdrive '
            - 'csproduct '
            - 'computersystem '
            - ' os '
            - ''
    condition: selection and not 1 of filter_main_* and not 1 of filter_optional_*
falsepositives:
    - False positives are to be expected from PowerShell scripts that might make use of additional binaries such as "mshta", "bitsadmin", etc. Apply additional filters for those scripts.
level: medium
```
