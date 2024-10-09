```sql
// Translated content (automatically translated on 08-10-2024 15:38:03):
(event.category in ("DNS","Url","IP")) and (endpoint.os="windows" and (url.address contains ".hostedrmm.com" or event.dns.request contains ".hostedrmm.com"))
```


# Original Sigma Rule:
```yaml
title: Potential Connectwise Automate (LabTech) RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.hostedrmm.com'
  condition: selection
id: 24aea3f1-7d41-4736-b083-bafb6ed85644
status: experimental
description: Detects potential network activity of Connectwise Automate (LabTech)
  RMM tool
author: LOLRMM Project
date: 2024-08-07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Connectwise Automate (LabTech)
level: medium
```