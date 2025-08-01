```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\msxsl.exe" and tgt.process.cmdline contains "http"))
```


# Original Sigma Rule:
```yaml
title: Remote XSL Execution Via Msxsl.EXE
id: 75d0a94e-6252-448d-a7be-d953dff527bb
status: test
description: Detects the execution of the "msxsl" binary with an "http" keyword in the command line. This might indicate a potential remote execution of XSL files.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1220/T1220.md
    - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Msxsl/
author: Swachchhanda Shrawan Poudel
date: 2023-11-09
tags:
    - attack.defense-evasion
    - attack.t1220
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\msxsl.exe'
        CommandLine|contains: 'http'
    condition: selection
falsepositives:
    - Msxsl is not installed by default and is deprecated, so unlikely on most systems.
level: high
```
