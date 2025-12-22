```sql
// Translated content (automatically translated on 22-12-2025 01:02:22):
event.type="Process Creation" and (endpoint.os="linux" and (tgt.process.cmdline contains " -name .htpasswd" or tgt.process.cmdline contains " -perm -4000 "))
```


# Original Sigma Rule:
```yaml
title: Linux Recon Indicators
id: 0cf7a157-8879-41a2-8f55-388dd23746b7
status: test
description: Detects events with patterns found in commands used for reconnaissance on linux systems
references:
    - https://github.com/sleventyeleven/linuxprivchecker/blob/0d701080bbf92efd464e97d71a70f97c6f2cd658/linuxprivchecker.py
author: Florian Roth (Nextron Systems)
date: 2022-06-20
tags:
    - attack.reconnaissance
    - attack.t1592.004
    - attack.credential-access
    - attack.t1552.001
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        CommandLine|contains:
            - ' -name .htpasswd'
            - ' -perm -4000 '
    condition: selection
falsepositives:
    - Legitimate administration activities
level: high
```
