```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "user_managed" or url.address contains "systemmanager.ru/dntu.en/rdp_view.htm") or (event.dns.request contains "user_managed" or event.dns.request contains "systemmanager.ru/dntu.en/rdp_view.htm")))
```


# Original Sigma Rule:
```yaml
title: Potential RDPView RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - user_managed
    - systemmanager.ru/dntu.en/rdp_view.htm
  condition: selection
id: 68ade31f-2e89-4455-af5a-f7ec0826ad39
status: experimental
description: Detects potential network activity of RDPView RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of RDPView
level: medium
```
