```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "user_managed" or url.address contains "guacamole.apache.org") or (event.dns.request contains "user_managed" or event.dns.request contains "guacamole.apache.org")))
```


# Original Sigma Rule:
```yaml
title: Potential Guacamole RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - user_managed
    - guacamole.apache.org
  condition: selection
id: 3ab12f88-dd15-4b80-9ecd-cf3ab4cc1faa
status: experimental
description: Detects potential network activity of Guacamole RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Guacamole
level: medium
```
