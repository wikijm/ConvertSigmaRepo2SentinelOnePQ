```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\htran.exe" or tgt.process.image.path contains "\lcx.exe") or (tgt.process.cmdline contains ".exe -tran " or tgt.process.cmdline contains ".exe -slave ")))
```


# Original Sigma Rule:
```yaml
title: HackTool - Htran/NATBypass Execution
id: f5e3b62f-e577-4e59-931e-0a15b2b94e1e
status: test
description: Detects executable names or flags used by Htran or Htran-like tools (e.g. NATBypass)
references:
    - https://github.com/HiwinCN/HTran
    - https://github.com/cw1997/NATBypass
author: Florian Roth (Nextron Systems)
date: 2022-12-27
modified: 2023-02-04
tags:
    - attack.command-and-control
    - attack.t1090
    - attack.s0040
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith:
            - '\htran.exe'
            - '\lcx.exe'
    selection_cli:
        CommandLine|contains:
            - '.exe -tran '
            - '.exe -slave '
    condition: 1 of selection_*
falsepositives:
    - Unknown
level: high
```
