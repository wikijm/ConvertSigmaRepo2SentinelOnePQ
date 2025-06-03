```sql
// Translated content (automatically translated on 03-06-2025 01:40:56):
(event.category in ("DNS","Url","IP")) and (endpoint.os="windows" and (url.address contains "imperosoftware.com/impero-connect/" or event.dns.request contains "imperosoftware.com/impero-connect/"))
```


# Original Sigma Rule:
```yaml
title: Potential Netop Remote Control (aka Impero Connect) RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - imperosoftware.com/impero-connect/
  condition: selection
id: a1e072c6-6662-4fed-8c3f-24731315a82a
status: experimental
description: Detects potential network activity of Netop Remote Control (aka Impero
  Connect) RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Netop Remote Control (aka Impero Connect)
level: medium
```
