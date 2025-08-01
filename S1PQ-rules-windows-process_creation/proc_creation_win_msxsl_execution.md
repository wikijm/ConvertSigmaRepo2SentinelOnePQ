```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and tgt.process.image.path contains "\msxsl.exe")
```


# Original Sigma Rule:
```yaml
title: Msxsl.EXE Execution
id: 9e50a8b3-dd05-4eb8-9153-bdb6b79d50b0
status: test
description: |
    Detects the execution of the MSXSL utility. This can be used to execute Extensible Stylesheet Language (XSL) files. These files are commonly used to describe the processing and rendering of data within XML files.
    Adversaries can abuse this functionality to execute arbitrary files while potentially bypassing application whitelisting defenses.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1220/T1220.md
    - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Msxsl/
author: Timur Zinniatullin, oscd.community
date: 2019-10-21
modified: 2023-11-09
tags:
    - attack.defense-evasion
    - attack.t1220
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\msxsl.exe'
    condition: selection
falsepositives:
    - Msxsl is not installed by default and is deprecated, so unlikely on most systems.
# Note: If you levreage this utility please consider adding additional filters. As this is looking for "any" type of execition
level: medium
```
