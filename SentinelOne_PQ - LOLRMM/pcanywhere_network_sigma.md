```sql
// Translated content (automatically translated on 10-09-2026 01:58:18):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "user_managed" or event.dns.request contains "user_managed"))
```


# Original Sigma Rule:
```yaml
title: Potential pcAnywhere RMM Tool Network Activity
id: ed673768-6a23-4b61-994e-b410b2c36b65
status: experimental
description: |
    Detects potential network activity of pcAnywhere RMM tool
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
    - Legitimate use of pcAnywhere
level: medium
```
