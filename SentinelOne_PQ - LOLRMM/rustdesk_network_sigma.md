```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "rustdesk.com" or url.address contains "user_managed" or url.address contains "web.rustdesk.com" or url.address contains "api.rustdesk.com" or url.address contains "rs-ny.rustdesk.com") or (event.dns.request contains "rustdesk.com" or event.dns.request contains "user_managed" or event.dns.request contains "web.rustdesk.com" or event.dns.request contains "api.rustdesk.com" or event.dns.request contains "rs-ny.rustdesk.com")))
```


# Original Sigma Rule:
```yaml
title: Potential RustDesk RMM Tool Network Activity
id: 56f0c5a9-a83b-41ec-b9cf-f90c69b2e142
status: experimental
description: |
    Detects potential network activity of RustDesk RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2025-12-01
tags:
    - attack.execution
    - attack.t1219
logsource:
    product: windows
    category: network_connection
detection:
    selection:
        DestinationHostname|endswith:
            - rustdesk.com
            - user_managed
            - web.rustdesk.com
            - api.rustdesk.com
            - rs-ny.rustdesk.com
    condition: selection
falsepositives:
    - Legitimate use of RustDesk
level: medium
```
