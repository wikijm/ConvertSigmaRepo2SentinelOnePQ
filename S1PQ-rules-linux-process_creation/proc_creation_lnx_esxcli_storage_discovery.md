```sql
// Translated content (automatically translated on 02-08-2025 00:59:06):
event.type="Process Creation" and (endpoint.os="linux" and ((tgt.process.image.path contains "/esxcli" and tgt.process.cmdline contains "storage") and (tgt.process.cmdline contains " get" or tgt.process.cmdline contains " list")))
```


# Original Sigma Rule:
```yaml
title: ESXi Storage Information Discovery Via ESXCLI
id: f41dada5-3f56-4232-8503-3fb7f9cf2d60
status: test
description: Detects execution of the "esxcli" command with the "storage" flag in order to retrieve information about the storage status and other related information. Seen used by malware such as DarkSide and LockBit.
references:
    - https://www.trendmicro.com/en_us/research/21/e/darkside-linux-vms-targeted.html
    - https://www.trendmicro.com/en_us/research/22/a/analysis-and-Impact-of-lockbit-ransomwares-first-linux-and-vmware-esxi-variant.html
    - https://developer.broadcom.com/xapis/esxcli-command-reference/7.0.0/namespace/esxcli_storage.html
author: Nasreddine Bencherchali (Nextron Systems), Cedric Maurugeon
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
        CommandLine|contains: 'storage'
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
