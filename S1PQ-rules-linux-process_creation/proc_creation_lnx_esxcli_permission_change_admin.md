```sql
// Translated content (automatically translated on 22-12-2025 01:02:22):
event.type="Process Creation" and (endpoint.os="linux" and (tgt.process.image.path contains "/esxcli" and tgt.process.cmdline contains "system" and (tgt.process.cmdline contains " permission " and tgt.process.cmdline contains " set" and tgt.process.cmdline contains "Admin")))
```


# Original Sigma Rule:
```yaml
title: ESXi Admin Permission Assigned To Account Via ESXCLI
id: 9691f58d-92c1-4416-8bf3-2edd753ec9cf
status: test
description: Detects execution of the "esxcli" command with the "system" and "permission" flags in order to assign admin permissions to an account.
references:
    - https://developer.broadcom.com/xapis/esxcli-command-reference/7.0.0/namespace/esxcli_system.html
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-09-04
tags:
    - attack.persistence
    - attack.execution
    - attack.privilege-escalation
    - attack.t1059.012
    - attack.t1098
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: '/esxcli'
        CommandLine|contains: 'system'
        CommandLine|contains|all:
            - ' permission '
            - ' set'
            - 'Admin'
    condition: selection
falsepositives:
    - Legitimate administration activities
level: high
```
