```sql
// Translated content (automatically translated on 19-05-2025 02:08:23):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains "extrac32.exe" and tgt.process.cmdline contains ".cab") and tgt.process.cmdline matches ":[^\\\\]"))
```


# Original Sigma Rule:
```yaml
title: Suspicious Extrac32 Alternate Data Stream Execution
id: 4b13db67-0c45-40f1-aba8-66a1a7198a1e
status: test
description: Extract data from cab file and hide it in an alternate data stream
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Extrac32/
author: frack113
date: 2021-11-26
modified: 2022-12-30
tags:
    - attack.defense-evasion
    - attack.t1564.004
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - extrac32.exe
            - .cab
        CommandLine|re: ':[^\\]'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
