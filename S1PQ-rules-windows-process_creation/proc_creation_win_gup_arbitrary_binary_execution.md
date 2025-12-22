```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\\gup.exe" and tgt.process.image.path contains "\\explorer.exe") and (not ((tgt.process.image.path contains "\\explorer.exe" and tgt.process.cmdline contains "\\Notepad++\\notepad++.exe") or src.process.image.path contains "\\Notepad++\\updater\\" or not (tgt.process.cmdline matches "\.*")))))
```


# Original Sigma Rule:
```yaml
title: Arbitrary Binary Execution Using GUP Utility
id: d65aee4d-2292-4cea-b832-83accd6cfa43
status: test
description: Detects execution of the Notepad++ updater (gup) to launch other commands or executables
references:
    - https://twitter.com/nas_bench/status/1535322445439180803
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-06-10
modified: 2023-03-02
tags:
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\gup.exe'
        Image|endswith: '\explorer.exe'
    filter:
        Image|endswith: '\explorer.exe'
        CommandLine|contains: '\Notepad++\notepad++.exe'
    filter_parent:
        ParentImage|contains: '\Notepad++\updater\'
    filter_null:
        CommandLine: null
    condition: selection and not 1 of filter*
falsepositives:
    - Other parent binaries using GUP not currently identified
level: medium
```
