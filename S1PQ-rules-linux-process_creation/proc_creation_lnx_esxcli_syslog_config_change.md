```sql
// Translated content (automatically translated on 24-08-2025 01:00:28):
event.type="Process Creation" and (endpoint.os="linux" and (tgt.process.image.path contains "/esxcli" and (tgt.process.cmdline contains "system" and tgt.process.cmdline contains "syslog" and tgt.process.cmdline contains "config") and tgt.process.cmdline contains " set"))
```


# Original Sigma Rule:
```yaml
title: ESXi Syslog Configuration Change Via ESXCLI
id: 38eb1dbb-011f-40b1-a126-cf03a0210563
status: test
description: Detects changes to the ESXi syslog configuration via "esxcli"
references:
    - https://support.solarwinds.com/SuccessCenter/s/article/Configure-ESXi-Syslog-to-LEM?language=en_US
    - https://developer.broadcom.com/xapis/esxcli-command-reference/7.0.0/namespace/esxcli_system.html
author: Cedric Maurugeon
date: 2023-09-04
tags:
    - attack.defense-evasion
    - attack.execution
    - attack.t1562.001
    - attack.t1562.003
    - attack.t1059.012
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: '/esxcli'
        CommandLine|contains|all:
            - 'system'
            - 'syslog'
            - 'config'
        CommandLine|contains: ' set'
    condition: selection
falsepositives:
    - Legitimate administrative activities
level: medium
```
