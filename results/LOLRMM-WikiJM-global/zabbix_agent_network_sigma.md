```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "user_managed" or url.address contains "zabbix.com") or (event.dns.request contains "user_managed" or event.dns.request contains "zabbix.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Zabbix Agent RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - user_managed
    - zabbix.com
  condition: selection
id: dbb6ae92-593f-475a-a64e-8f100154096c
status: experimental
description: Detects potential network activity of Zabbix Agent RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Zabbix Agent
level: medium
```
