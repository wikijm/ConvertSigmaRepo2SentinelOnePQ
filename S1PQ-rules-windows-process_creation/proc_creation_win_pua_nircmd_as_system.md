```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and tgt.process.cmdline contains " runassystem ") | columns tgt.process.cmdline,src.process.cmdline
```


# Original Sigma Rule:
```yaml
title: PUA - NirCmd Execution As LOCAL SYSTEM
id: d9047477-0359-48c9-b8c7-792cedcdc9c4
status: test
description: Detects the use of NirCmd tool for command execution as SYSTEM user
references:
    - https://www.nirsoft.net/utils/nircmd.html
    - https://www.winhelponline.com/blog/run-program-as-system-localsystem-account-windows/
    - https://www.nirsoft.net/utils/nircmd2.html#using
author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
date: 2022-01-24
modified: 2023-02-13
tags:
    - attack.execution
    - attack.t1569.002
    - attack.s0029
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: ' runassystem '
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Legitimate use by administrators
level: high
```
