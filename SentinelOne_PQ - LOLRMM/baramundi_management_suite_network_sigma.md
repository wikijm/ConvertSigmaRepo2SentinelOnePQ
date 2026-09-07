```sql
// Translated content (automatically translated on 07-09-2026 01:44:50):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".baramundi.com" or url.address contains "www.baramundi.com" or url.address contains "docs.baramundi.com" or url.address contains "isodownload.baramundi.com") or (event.dns.request contains ".baramundi.com" or event.dns.request contains "www.baramundi.com" or event.dns.request contains "docs.baramundi.com" or event.dns.request contains "isodownload.baramundi.com")))
```


# Original Sigma Rule:
```yaml
title: Potential baramundi Management Suite RMM Tool Network Activity
id: 6a3f6976-7dc0-5aaa-a981-b4f18b374b6d
status: experimental
description: |
    Detects potential network activity of baramundi Management Suite RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-05-18
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
            - '*.baramundi.com'
            - 'www.baramundi.com'
            - 'docs.baramundi.com'
            - 'isodownload.baramundi.com'
    condition: selection
falsepositives:
    - Legitimate use of baramundi Management Suite
level: medium
```
