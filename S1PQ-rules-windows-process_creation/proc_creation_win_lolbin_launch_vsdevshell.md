```sql
// Translated content (automatically translated on 05-08-2025 02:26:42):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "Launch-VsDevShell.ps1" and (tgt.process.cmdline contains "VsWherePath " or tgt.process.cmdline contains "VsInstallationPath ")))
```


# Original Sigma Rule:
```yaml
title: Launch-VsDevShell.PS1 Proxy Execution
id: 45d3a03d-f441-458c-8883-df101a3bb146
status: test
description: Detects the use of the 'Launch-VsDevShell.ps1' Microsoft signed script to execute commands.
references:
    - https://twitter.com/nas_bench/status/1535981653239255040
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-08-19
tags:
    - attack.defense-evasion
    - attack.t1216.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_script:
        CommandLine|contains: 'Launch-VsDevShell.ps1'
    selection_flags:
        CommandLine|contains:
            - 'VsWherePath '
            - 'VsInstallationPath '
    condition: all of selection_*
falsepositives:
    - Legitimate usage of the script by a developer
level: medium
```
