```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains "diantz.exe" and tgt.process.cmdline contains ".cab") and tgt.process.cmdline matches ":[^\\\\]"))
```


# Original Sigma Rule:
```yaml
title: Suspicious Diantz Alternate Data Stream Execution
id: 6b369ced-4b1d-48f1-b427-fdc0de0790bd
status: test
description: Compress target file into a cab file stored in the Alternate Data Stream (ADS) of the target file.
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Diantz/
author: frack113
date: 2021-11-26
modified: 2022-12-31
tags:
    - attack.defense-evasion
    - attack.t1564.004
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - diantz.exe
            - .cab
        CommandLine|re: ':[^\\]'
    condition: selection
falsepositives:
    - Very Possible
level: medium
```
