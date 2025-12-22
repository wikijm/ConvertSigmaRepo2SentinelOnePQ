```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "pilixo.com" or url.address contains "download.pilixo.com" or url.address contains ".pilixo.com") or (event.dns.request contains "pilixo.com" or event.dns.request contains "download.pilixo.com" or event.dns.request contains ".pilixo.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Pilixo RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - pilixo.com
    - download.pilixo.com
    - '*.pilixo.com'
  condition: selection
id: 11be93dd-95ec-496f-902b-77c07a26a467
status: experimental
description: Detects potential network activity of Pilixo RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Pilixo
level: medium
```
