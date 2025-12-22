```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "user_managed" or url.address contains "simple-help.com") or (event.dns.request contains "user_managed" or event.dns.request contains "simple-help.com")))
```


# Original Sigma Rule:
```yaml
title: Potential SimpleHelp RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - user_managed
    - simple-help.com
  condition: selection
id: 79838aad-36c1-4ca7-b3f4-9f5334d242ae
status: experimental
description: Detects potential network activity of SimpleHelp RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of SimpleHelp
level: medium
```
