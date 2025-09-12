```sql
// Translated content (automatically translated on 12-09-2025 01:21:22):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "runsmart.io" or event.dns.request contains "runsmart.io"))
```


# Original Sigma Rule:
```yaml
title: Potential RunSmart RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - runsmart.io
  condition: selection
id: c95bdc66-f183-4eed-9c0a-8278185269bf
status: experimental
description: Detects potential network activity of RunSmart RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of RunSmart
level: medium
```
