```sql
// Translated content (automatically translated on 30-11-2025 00:59:06):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and (url.address contains ".server-eye.de" or event.dns.request contains ".server-eye.de"))
```


# Original Sigma Rule:
```yaml
title: Potential ServerEye RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.server-eye.de'
  condition: selection
id: cb61655a-fb52-45a6-97a7-8de1f1320c2a
status: experimental
description: Detects potential network activity of ServerEye RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of ServerEye
level: medium
```
