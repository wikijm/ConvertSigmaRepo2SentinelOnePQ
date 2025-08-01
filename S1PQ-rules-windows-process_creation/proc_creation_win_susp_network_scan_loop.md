```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains "for " or tgt.process.cmdline contains "foreach ") and (tgt.process.cmdline contains "nslookup" or tgt.process.cmdline contains "ping")))
```


# Original Sigma Rule:
```yaml
title: Suspicious Scan Loop Network
id: f8ad2e2c-40b6-4117-84d7-20b89896ab23
status: test
description: Adversaries may attempt to get a listing of other systems by IP address, hostname, or other logical identifier on a network that may be used for Lateral Movement from the current system
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1018/T1018.md
    - https://ss64.com/nt/for.html
    - https://ss64.com/ps/foreach-object.html
author: frack113
date: 2022-03-12
tags:
    - attack.execution
    - attack.t1059
    - attack.discovery
    - attack.t1018
logsource:
    category: process_creation
    product: windows
detection:
    selection_loop:
        CommandLine|contains:
            - 'for '
            - 'foreach '
    selection_tools:
        CommandLine|contains:
            - 'nslookup'
            - 'ping'
    condition: all of selection_*
falsepositives:
    - Legitimate script
level: medium
```
