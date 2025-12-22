```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "user_managed" or url.address contains "zabbix.com") or (event.dns.request contains "user_managed" or event.dns.request contains "zabbix.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Zabbix Agent RMM Tool Network Activity
id: 7f5b4e26-420b-46dd-a3c4-226256c4d84a
status: experimental
description: |
    Detects potential network activity of Zabbix Agent RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2025-12-01
tags:
    - attack.execution
    - attack.t1219
logsource:
    product: windows
    category: network_connection
detection:
    selection:
        DestinationHostname|endswith:
            - user_managed
            - zabbix.com
    condition: selection
falsepositives:
    - Legitimate use of Zabbix Agent
level: medium
```
