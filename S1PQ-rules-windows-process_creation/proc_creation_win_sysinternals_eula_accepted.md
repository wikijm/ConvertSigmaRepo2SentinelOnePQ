```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains " -accepteula" or tgt.process.cmdline contains " /accepteula" or tgt.process.cmdline contains " –accepteula" or tgt.process.cmdline contains " —accepteula" or tgt.process.cmdline contains " ―accepteula"))
```


# Original Sigma Rule:
```yaml
title: Potential Execution of Sysinternals Tools
id: 7cccd811-7ae9-4ebe-9afd-cb5c406b824b
related:
    - id: 25ffa65d-76d8-4da5-a832-3f2b0136e133
      type: derived
status: test
description: Detects command lines that contain the 'accepteula' flag which could be a sign of execution of one of the Sysinternals tools
references:
    - https://twitter.com/Moti_B/status/1008587936735035392
author: Markus Neis
date: 2017-08-28
modified: 2024-03-13
tags:
    - attack.resource-development
    - attack.t1588.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|windash: ' -accepteula'
    condition: selection
falsepositives:
    - Legitimate use of SysInternals tools
    - Programs that use the same command line flag
level: low
```
