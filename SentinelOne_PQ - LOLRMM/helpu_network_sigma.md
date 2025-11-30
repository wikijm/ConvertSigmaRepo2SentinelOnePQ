```sql
// Translated content (automatically translated on 30-11-2025 00:59:06):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "helpu.co.kr" or url.address contains ".helpu.co.kr") or (event.dns.request contains "helpu.co.kr" or event.dns.request contains ".helpu.co.kr")))
```


# Original Sigma Rule:
```yaml
title: Potential HelpU RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - helpu.co.kr
    - '*.helpu.co.kr'
  condition: selection
id: f7818a0e-2039-4ad5-ae84-891d93dff067
status: experimental
description: Detects potential network activity of HelpU RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of HelpU
level: medium
```
