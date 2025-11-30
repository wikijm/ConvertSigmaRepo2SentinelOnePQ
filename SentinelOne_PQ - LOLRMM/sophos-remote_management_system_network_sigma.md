```sql
// Translated content (automatically translated on 30-11-2025 00:59:06):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".sophos.com" or url.address contains ".sophosupd.com" or url.address contains ".sophosupd.net" or url.address contains "community.sophos.com/on-premise-endpoint/f/sophos-endpoint-software/5725/sophos-remote-management-system") or (event.dns.request contains ".sophos.com" or event.dns.request contains ".sophosupd.com" or event.dns.request contains ".sophosupd.net" or event.dns.request contains "community.sophos.com/on-premise-endpoint/f/sophos-endpoint-software/5725/sophos-remote-management-system")))
```


# Original Sigma Rule:
```yaml
title: Potential Sophos-Remote Management System RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.sophos.com'
    - '*.sophosupd.com'
    - '*.sophosupd.net'
    - community.sophos.com/on-premise-endpoint/f/sophos-endpoint-software/5725/sophos-remote-management-system
  condition: selection
id: 78b4d010-29f8-4fea-b406-c2c335039e41
status: experimental
description: Detects potential network activity of Sophos-Remote Management System
  RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Sophos-Remote Management System
level: medium
```
