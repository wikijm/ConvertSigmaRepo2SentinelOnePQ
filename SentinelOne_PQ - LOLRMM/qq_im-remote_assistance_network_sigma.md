```sql
// Translated content (automatically translated on 16-07-2025 00:56:15):
(event.category in ("DNS","Url","IP")) and (endpoint.os="windows" and ((url.address contains ".mdt.qq.com" or url.address contains ".desktop.qq.com" or url.address contains "upload_data.qq.com" or url.address contains "qq-messenger.en.softonic.com") or (event.dns.request contains ".mdt.qq.com" or event.dns.request contains ".desktop.qq.com" or event.dns.request contains "upload_data.qq.com" or event.dns.request contains "qq-messenger.en.softonic.com")))
```


# Original Sigma Rule:
```yaml
title: Potential QQ IM-remote assistance RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.mdt.qq.com'
    - '*.desktop.qq.com'
    - upload_data.qq.com
    - qq-messenger.en.softonic.com
  condition: selection
id: a433daa3-deae-474a-9958-36cb9b287bb4
status: experimental
description: Detects potential network activity of QQ IM-remote assistance RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of QQ IM-remote assistance
level: medium
```
