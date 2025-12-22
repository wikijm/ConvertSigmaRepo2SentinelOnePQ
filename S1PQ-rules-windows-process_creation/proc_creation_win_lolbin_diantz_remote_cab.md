```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "diantz.exe" and tgt.process.cmdline contains " \\\\" and tgt.process.cmdline contains ".cab"))
```


# Original Sigma Rule:
```yaml
title: Suspicious Diantz Download and Compress Into a CAB File
id: 185d7418-f250-42d0-b72e-0c8b70661e93
status: test
description: Download and compress a remote file and store it in a cab file on local machine.
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Diantz/
author: frack113
date: 2021-11-26
modified: 2022-08-13
tags:
    - attack.command-and-control
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - diantz.exe
            - ' \\\\'
            - '.cab'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
