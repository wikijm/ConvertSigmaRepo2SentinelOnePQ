```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "prod.addigy.com" or url.address contains "grtmprod.addigy.com" or url.address contains "agents.addigy.com") or (event.dns.request contains "prod.addigy.com" or event.dns.request contains "grtmprod.addigy.com" or event.dns.request contains "agents.addigy.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Addigy RMM Tool Network Activity
id: 43757bb8-b54f-41be-9e96-8099c0dc9a16
status: experimental
description: |
    Detects potential network activity of Addigy RMM tool
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
            - prod.addigy.com
            - grtmprod.addigy.com
            - agents.addigy.com
    condition: selection
falsepositives:
    - Legitimate use of Addigy
level: medium
```
