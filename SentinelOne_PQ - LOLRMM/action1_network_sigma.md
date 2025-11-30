```sql
// Translated content (automatically translated on 30-11-2025 00:59:06):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".action1.com" or url.address contains "a1-backend-packages.s3.amazonaws.com") or (event.dns.request contains ".action1.com" or event.dns.request contains "a1-backend-packages.s3.amazonaws.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Action1 RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.action1.com'
    - a1-backend-packages.s3.amazonaws.com
  condition: selection
id: 5a513b93-4825-4b09-b50a-e073e390bc96
status: experimental
description: Detects potential network activity of Action1 RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Action1
level: medium
```
