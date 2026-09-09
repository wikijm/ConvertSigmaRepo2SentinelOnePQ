```sql
// Translated content (automatically translated on 09-09-2026 02:01:10):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".internetid.ru" or url.address contains "rmansys.ru") or (event.dns.request contains ".internetid.ru" or event.dns.request contains "rmansys.ru")))
```


# Original Sigma Rule:
```yaml
title: Potential Remote Manipulator System RMM Tool Network Activity
id: 4ab8f777-1476-417d-8ac4-9c70c46a79ee
status: experimental
description: |
    Detects potential network activity of Remote Manipulator System RMM tool
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
        DestinationHostname|endswith:
            - '*.internetid.ru'
            - 'rmansys.ru'
    condition: selection
falsepositives:
    - Legitimate use of Remote Manipulator System
level: medium
```
