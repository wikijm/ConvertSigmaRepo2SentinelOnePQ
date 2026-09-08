```sql
// Translated content (automatically translated on 08-09-2026 01:56:19):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".sophos.com" or url.address contains ".sophosupd.com" or url.address contains ".sophosupd.net") or (event.dns.request contains ".sophos.com" or event.dns.request contains ".sophosupd.com" or event.dns.request contains ".sophosupd.net")))
```


# Original Sigma Rule:
```yaml
title: Potential Sophos-Remote Management System RMM Tool Network Activity
id: a6e96201-a321-468f-9600-829c7a4a8b9c
status: experimental
description: |
    Detects potential network activity of Sophos-Remote Management System RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2025-12-01
modified: 2026-09-02
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: network_connection
detection:
    selection:
        DestinationHostname|endswith:
            - '*.sophos.com'
            - '*.sophosupd.com'
            - '*.sophosupd.net'
    condition: selection
falsepositives:
    - Legitimate use of Sophos-Remote Management System
level: medium
```
