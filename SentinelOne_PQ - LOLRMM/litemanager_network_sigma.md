```sql
// Translated content (automatically translated on 09-09-2026 02:01:10):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".litemanager.ru" or url.address contains ".litemanager.com" or url.address contains "litemanager.com") or (event.dns.request contains ".litemanager.ru" or event.dns.request contains ".litemanager.com" or event.dns.request contains "litemanager.com")))
```


# Original Sigma Rule:
```yaml
title: Potential LiteManager RMM Tool Network Activity
id: 6e3e81a5-8133-4a43-ba08-31d8279ba7f1
status: experimental
description: |
    Detects potential network activity of LiteManager RMM tool
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
            - '*.litemanager.ru'
            - '*.litemanager.com'
            - 'litemanager.com'
    condition: selection
falsepositives:
    - Legitimate use of LiteManager
level: medium
```
