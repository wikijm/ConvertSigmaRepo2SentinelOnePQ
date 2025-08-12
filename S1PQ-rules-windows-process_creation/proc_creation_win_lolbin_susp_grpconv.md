```sql
// Translated content (automatically translated on 12-08-2025 02:06:47):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "grpconv.exe -o" or tgt.process.cmdline contains "grpconv -o"))
```


# Original Sigma Rule:
```yaml
title: Suspicious GrpConv Execution
id: f14e169e-9978-4c69-acb3-1cff8200bc36
status: test
description: Detects the suspicious execution of a utility to convert Windows 3.x .grp files or for persistence purposes by malicious software or actors
references:
    - https://twitter.com/0gtweet/status/1526833181831200770
author: Florian Roth (Nextron Systems)
date: 2022-05-19
tags:
    - attack.persistence
    - attack.t1547
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'grpconv.exe -o'
            - 'grpconv -o'
    condition: selection
falsepositives:
    - Unknown
level: high
```
