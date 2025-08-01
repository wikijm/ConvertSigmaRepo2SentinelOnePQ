```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and src.process.image.path contains "\pcwrun.exe") | columns ComputerName,tgt.process.user,src.process.cmdline,tgt.process.cmdline
```


# Original Sigma Rule:
```yaml
title: Indirect Command Execution By Program Compatibility Wizard
id: b97cd4b1-30b8-4a9d-bd72-6293928d52bc
status: test
description: Detect indirect command execution via Program Compatibility Assistant pcwrun.exe
references:
    - https://twitter.com/pabraeken/status/991335019833708544
    - https://lolbas-project.github.io/lolbas/Binaries/Pcwrun/
author: A. Sungurov , oscd.community
date: 2020-10-12
modified: 2021-11-27
tags:
    - attack.defense-evasion
    - attack.t1218
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\pcwrun.exe'
    condition: selection
fields:
    - ComputerName
    - User
    - ParentCommandLine
    - CommandLine
falsepositives:
    - Need to use extra processing with 'unique_count' / 'filter' to focus on outliers as opposed to commonly seen artifacts
    - Legit usage of scripts
level: low
```
