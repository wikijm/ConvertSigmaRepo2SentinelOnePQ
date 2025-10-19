```sql
// Translated content (automatically translated on 19-10-2025 00:59:23):
event.type="Process Creation" and (endpoint.os="linux" and ((tgt.process.image.path contains "/esxcli" and tgt.process.cmdline contains "system") and (tgt.process.cmdline contains " get" or tgt.process.cmdline contains " list")))
```


# Original Sigma Rule:
```yaml
title: ESXi System Information Discovery Via ESXCLI
id: e80273e1-9faf-40bc-bd85-dbaff104c4e9
status: test
description: Detects execution of the "esxcli" command with the "system" flag in order to retrieve information about the different component of the system. Such as accounts, modules, NTP, etc.
references:
    - https://www.crowdstrike.com/blog/hypervisor-jackpotting-ecrime-actors-increase-targeting-of-esxi-servers/
    - https://developer.broadcom.com/xapis/esxcli-command-reference/7.0.0/namespace/esxcli_system.html
author: Cedric Maurugeon
date: 2023-09-04
tags:
    - attack.discovery
    - attack.execution
    - attack.t1033
    - attack.t1007
    - attack.t1059.012
logsource:
    category: process_creation
    product: linux
detection:
    selection_img:
        Image|endswith: '/esxcli'
        CommandLine|contains: 'system'
    selection_cli:
        CommandLine|contains:
            - ' get'
            - ' list'
    condition: all of selection_*
falsepositives:
    - Legitimate administration activities
level: medium
```
