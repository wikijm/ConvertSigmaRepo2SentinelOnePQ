```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "user_managed" or event.dns.request contains "user_managed"))
```


# Original Sigma Rule:
```yaml
title: Potential Apple Remote Desktop RMM Tool Network Activity
id: b6f5a66a-ed37-429a-8488-c196186726ca
status: experimental
description: |
    Detects potential network activity of Apple Remote Desktop RMM tool
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
        DestinationHostname|endswith: user_managed
    condition: selection
falsepositives:
    - Legitimate use of Apple Remote Desktop
level: medium
```
