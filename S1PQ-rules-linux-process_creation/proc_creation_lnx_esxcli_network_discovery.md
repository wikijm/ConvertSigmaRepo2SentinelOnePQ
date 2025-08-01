```sql
// Translated content (automatically translated on 02-08-2025 00:59:06):
event.type="Process Creation" and (endpoint.os="linux" and ((tgt.process.image.path contains "/esxcli" and tgt.process.cmdline contains "network") and (tgt.process.cmdline contains " get" or tgt.process.cmdline contains " list")))
```


# Original Sigma Rule:
```yaml
title: ESXi Network Configuration Discovery Via ESXCLI
id: 33e814e0-1f00-4e43-9c34-31fb7ae2b174
status: test
description: Detects execution of the "esxcli" command with the "network" flag in order to retrieve information about the network configuration.
references:
    - https://www.crowdstrike.com/blog/hypervisor-jackpotting-ecrime-actors-increase-targeting-of-esxi-servers/
    - https://developer.broadcom.com/xapis/esxcli-command-reference/7.0.0/namespace/esxcli_network.html
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
        CommandLine|contains: 'network'
    selection_cli:
        CommandLine|contains:
            - ' get'
            - ' list'
    condition: all of selection_*
falsepositives:
    - Legitimate administration activities
# Note: level can be reduced to low in some envs
level: medium
```
