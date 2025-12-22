```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "beyondtrust.com/brand/bomgar" or event.dns.request contains "beyondtrust.com/brand/bomgar"))
```


# Original Sigma Rule:
```yaml
title: Potential Bomgar RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - beyondtrust.com/brand/bomgar
  condition: selection
id: f3308c30-40e3-4604-83d3-83d7e6b9583b
status: experimental
description: Detects potential network activity of Bomgar RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Bomgar
level: medium
```
