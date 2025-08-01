```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains "-u " and tgt.process.cmdline contains "-p ") and (tgt.process.cmdline contains "^USER^" or tgt.process.cmdline contains "^PASS^")))
```


# Original Sigma Rule:
```yaml
title: HackTool - Hydra Password Bruteforce Execution
id: aaafa146-074c-11eb-adc1-0242ac120002
status: test
description: Detects command line parameters used by Hydra password guessing hack tool
references:
    - https://github.com/vanhauser-thc/thc-hydra
author: Vasiliy Burov
date: 2020-10-05
modified: 2023-02-04
tags:
    - attack.credential-access
    - attack.t1110
    - attack.t1110.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - '-u '
            - '-p '
        CommandLine|contains:
            - '^USER^'
            - '^PASS^'
    condition: selection
falsepositives:
    - Software that uses the caret encased keywords PASS and USER in its command line
level: high
```
