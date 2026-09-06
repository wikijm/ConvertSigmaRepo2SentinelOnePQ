```sql
// Translated content (automatically translated on 06-09-2026 01:47:37):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "cdn.teleport.dev" or url.address contains "reporting-connect.teleportinfra.sh" or url.address contains "usage.teleport.dev" or url.address contains ".teleport.sh" or url.address contains "user_managed") or (event.dns.request contains "cdn.teleport.dev" or event.dns.request contains "reporting-connect.teleportinfra.sh" or event.dns.request contains "usage.teleport.dev" or event.dns.request contains ".teleport.sh" or event.dns.request contains "user_managed")))
```


# Original Sigma Rule:
```yaml
title: Potential Teleport Connect RMM Tool Network Activity
id: 031bf8ad-a5d5-5d00-857b-bedeed51eaf5
status: experimental
description: |
    Detects potential network activity of Teleport Connect RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-08-18
modified: 2026-09-02
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: network_connection
detection:
    selection:
        DestinationHostname|endswith:
            - 'cdn.teleport.dev'
            - 'reporting-connect.teleportinfra.sh'
            - 'usage.teleport.dev'
            - '*.teleport.sh'
            - 'user_managed'
    condition: selection
falsepositives:
    - Legitimate use of Teleport Connect
level: medium
```
