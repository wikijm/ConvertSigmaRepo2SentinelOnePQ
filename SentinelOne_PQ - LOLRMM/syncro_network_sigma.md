```sql
// Translated content (automatically translated on 30-11-2025 00:59:06):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "kabuto.io" or url.address contains ".syncromsp.com" or url.address contains ".syncroapi.com" or url.address contains "syncromsp.com" or url.address contains "servably.com" or url.address contains "ld.aurelius.host" or url.address contains "app.kabuto.io " or url.address contains ".kabutoservices.com" or url.address contains "repairshopr.com" or url.address contains "kabutoservices.com" or url.address contains "attachments.servably.com") or (event.dns.request contains "kabuto.io" or event.dns.request contains ".syncromsp.com" or event.dns.request contains ".syncroapi.com" or event.dns.request contains "syncromsp.com" or event.dns.request contains "servably.com" or event.dns.request contains "ld.aurelius.host" or event.dns.request contains "app.kabuto.io " or event.dns.request contains ".kabutoservices.com" or event.dns.request contains "repairshopr.com" or event.dns.request contains "kabutoservices.com" or event.dns.request contains "attachments.servably.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Syncro RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - kabuto.io
    - '*.syncromsp.com'
    - '*.syncroapi.com'
    - syncromsp.com
    - servably.com
    - ld.aurelius.host
    - 'app.kabuto.io '
    - '*.kabutoservices.com'
    - repairshopr.com
    - kabutoservices.com
    - attachments.servably.com
  condition: selection
id: a6178ede-3a67-4e98-8285-c0e5a99c7777
status: experimental
description: Detects potential network activity of Syncro RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Syncro
level: medium
```
