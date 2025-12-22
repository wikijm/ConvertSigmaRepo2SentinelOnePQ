```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains "au.pcmag.com/utilities/21470/webex-pcnow" or event.dns.request contains "au.pcmag.com/utilities/21470/webex-pcnow"))
```


# Original Sigma Rule:
```yaml
title: Potential Pcnow RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - au.pcmag.com/utilities/21470/webex-pcnow
  condition: selection
id: f3ce42d7-b932-4009-9d84-6ff8c6385b19
status: experimental
description: Detects potential network activity of Pcnow RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Pcnow
level: medium
```
