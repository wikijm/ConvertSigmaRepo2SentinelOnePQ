```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains " --adcs " and tgt.process.cmdline contains " --port "))
```


# Original Sigma Rule:
```yaml
title: HackTool - ADCSPwn Execution
id: cd8c163e-a19b-402e-bdd5-419ff5859f12
status: test
description: Detects command line parameters used by ADCSPwn, a tool to escalate privileges in an active directory network by coercing authenticate from machine accounts and relaying to the certificate service
references:
    - https://github.com/bats3c/ADCSPwn
author: Florian Roth (Nextron Systems)
date: 2021-07-31
modified: 2023-02-04
tags:
    - attack.collection
    - attack.credential-access
    - attack.t1557.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - ' --adcs '
            - ' --port '
    condition: selection
falsepositives:
    - Unlikely
level: high
```
