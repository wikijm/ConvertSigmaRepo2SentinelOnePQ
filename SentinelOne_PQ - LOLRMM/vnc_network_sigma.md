```sql
// Translated content (automatically translated on 06-09-2026 01:47:37):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "user_managed" or event.dns.request contains "user_managed"))
```


# Original Sigma Rule:
```yaml
title: Potential VNC RMM Tool Network Activity
id: 9daee246-13b9-49b9-b68b-520b55b2eea8
status: experimental
description: |
    Detects potential network activity of VNC RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2025-12-01
modified: 2026-09-02
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: network_connection
detection:
    selection:
        DestinationHostname|endswith: 'user_managed'
    condition: selection
falsepositives:
    - Legitimate use of VNC
level: medium
```
