```sql
// Translated content (automatically translated on 30-11-2025 00:59:06):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "goto.com" or url.address contains ".getgo.com" or url.address contains ".fastsupport.com" or url.address contains ".gotoassist.com" or url.address contains "helpme.net" or url.address contains ".gotoassist.me" or url.address contains ".gotoassist.at" or url.address contains ".desktopstreaming.com") or (event.dns.request contains "goto.com" or event.dns.request contains ".getgo.com" or event.dns.request contains ".fastsupport.com" or event.dns.request contains ".gotoassist.com" or event.dns.request contains "helpme.net" or event.dns.request contains ".gotoassist.me" or event.dns.request contains ".gotoassist.at" or event.dns.request contains ".desktopstreaming.com")))
```


# Original Sigma Rule:
```yaml
title: Potential GoToAssist RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - goto.com
    - '*.getgo.com'
    - '*.fastsupport.com'
    - '*.gotoassist.com'
    - helpme.net
    - '*.gotoassist.me'
    - '*.gotoassist.at'
    - '*.desktopstreaming.com'
  condition: selection
id: 35baa228-9b56-416d-9652-d696f35ca87b
status: experimental
description: Detects potential network activity of GoToAssist RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of GoToAssist
level: medium
```
