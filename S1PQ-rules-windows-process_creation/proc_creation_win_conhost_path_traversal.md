```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.cmdline contains "conhost" and tgt.process.cmdline contains "/../../"))
```


# Original Sigma Rule:
```yaml
title: Conhost.exe CommandLine Path Traversal
id: ee5e119b-1f75-4b34-add8-3be976961e39
status: test
description: detects the usage of path traversal in conhost.exe indicating possible command/argument confusion/hijacking
references:
    - https://pentestlab.blog/2020/07/06/indirect-command-execution/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-06-14
tags:
    - attack.execution
    - attack.t1059.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentCommandLine|contains: 'conhost'
        CommandLine|contains: '/../../'
    condition: selection
falsepositives:
    - Unlikely
level: high
```
