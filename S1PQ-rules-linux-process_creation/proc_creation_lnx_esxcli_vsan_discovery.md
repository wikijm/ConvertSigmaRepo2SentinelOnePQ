```sql
// Translated content (automatically translated on 31-05-2025 00:54:55):
event.type="Process Creation" and (endpoint.os="linux" and ((tgt.process.image.path contains "/esxcli" and tgt.process.cmdline contains "vsan") and (tgt.process.cmdline contains " get" or tgt.process.cmdline contains " list")))
```


# Original Sigma Rule:
```yaml
title: ESXi VSAN Information Discovery Via ESXCLI
id: d54c2f06-aca9-4e2b-81c9-5317858f4b79
status: test
description: Detects execution of the "esxcli" command with the "vsan" flag in order to retrieve information about virtual storage. Seen used by malware such as DarkSide.
references:
    - https://www.trendmicro.com/en_us/research/21/e/darkside-linux-vms-targeted.html
    - https://www.trendmicro.com/en_us/research/22/a/analysis-and-Impact-of-lockbit-ransomwares-first-linux-and-vmware-esxi-variant.html
    - https://developer.broadcom.com/xapis/esxcli-command-reference/7.0.0/namespace/esxcli_vsan.html
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
        CommandLine|contains: 'vsan'
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
