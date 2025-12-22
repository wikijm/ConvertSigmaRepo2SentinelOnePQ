```sql
// Translated content (automatically translated on 22-12-2025 01:02:22):
event.type="Process Creation" and (endpoint.os="linux" and (tgt.process.image.path contains "/esxcli" and (tgt.process.cmdline contains "system " and tgt.process.cmdline contains "account " and tgt.process.cmdline contains "add ")))
```


# Original Sigma Rule:
```yaml
title: ESXi Account Creation Via ESXCLI
id: b28e4eb3-8bbc-4f0c-819f-edfe8e2f25db
status: test
description: Detects user account creation on ESXi system via esxcli
references:
    - https://developer.broadcom.com/xapis/esxcli-command-reference/7.0.0/namespace/esxcli_system.html
author: Cedric Maurugeon
date: 2023-08-22
tags:
    - attack.persistence
    - attack.execution
    - attack.t1136
    - attack.t1059.012
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: '/esxcli'
        CommandLine|contains|all:
            - 'system '
            - 'account '
            - 'add '
    condition: selection
falsepositives:
    - Legitimate administration activities
level: medium
```
