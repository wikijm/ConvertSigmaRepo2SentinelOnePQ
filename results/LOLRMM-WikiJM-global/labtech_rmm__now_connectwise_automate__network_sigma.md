```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "connectwise.com" or event.dns.request contains "connectwise.com"))
```


# Original Sigma Rule:
```yaml
title: Potential LabTech RMM (Now ConnectWise Automate) RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - connectwise.com
  condition: selection
id: 96f37a1b-04e0-47ea-bdb3-238f903e8e0d
status: experimental
description: Detects potential network activity of LabTech RMM (Now ConnectWise Automate)
  RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of LabTech RMM (Now ConnectWise Automate)
level: medium
```
