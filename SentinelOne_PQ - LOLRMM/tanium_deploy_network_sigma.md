```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "tanium.com/products/tanium-deploy" or event.dns.request contains "tanium.com/products/tanium-deploy"))
```


# Original Sigma Rule:
```yaml
title: Potential Tanium Deploy RMM Tool Network Activity
id: f93aa9bc-cbc4-436d-89be-617d57b96db7
status: experimental
description: |
    Detects potential network activity of Tanium Deploy RMM tool
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
        DestinationHostname|endswith: tanium.com/products/tanium-deploy
    condition: selection
falsepositives:
    - Legitimate use of Tanium Deploy
level: medium
```
