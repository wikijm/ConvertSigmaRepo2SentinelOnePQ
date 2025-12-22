```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".pcvisit.de" or url.address contains "pcvisit.de") or (event.dns.request contains ".pcvisit.de" or event.dns.request contains "pcvisit.de")))
```


# Original Sigma Rule:
```yaml
title: Potential Pcvisit RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.pcvisit.de'
    - pcvisit.de
  condition: selection
id: 75e41cc0-eaa9-4795-b240-8b679fb9862e
status: experimental
description: Detects potential network activity of Pcvisit RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Pcvisit
level: medium
```
