```sql
// Translated content (automatically translated on 22-12-2025 01:49:27):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "mdmsupport.comodo.com" or url.address contains ".itsm-us1.comodo.com" or url.address contains ".cmdm.comodo.com" or url.address contains "remoteaccess.itarian.com" or url.address contains "servicedesk.itarian.com") or (event.dns.request contains "mdmsupport.comodo.com" or event.dns.request contains ".itsm-us1.comodo.com" or event.dns.request contains ".cmdm.comodo.com" or event.dns.request contains "remoteaccess.itarian.com" or event.dns.request contains "servicedesk.itarian.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Itarian RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - mdmsupport.comodo.com
    - '*.itsm-us1.comodo.com'
    - '*.cmdm.comodo.com'
    - remoteaccess.itarian.com
    - servicedesk.itarian.com
  condition: selection
id: e125647e-f920-4f3f-b3de-4bed2a58e51e
status: experimental
description: Detects potential network activity of Itarian RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Itarian
level: medium
```
