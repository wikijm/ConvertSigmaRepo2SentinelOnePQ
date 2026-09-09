```sql
// Translated content (automatically translated on 09-09-2026 02:01:10):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".weezo.me" or url.address contains "weezo.net" or url.address contains ".weezo.net" or url.address contains "weezo.en.softonic.com") or (event.dns.request contains ".weezo.me" or event.dns.request contains "weezo.net" or event.dns.request contains ".weezo.net" or event.dns.request contains "weezo.en.softonic.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Weezo RMM Tool Network Activity
id: e7a74923-a27d-4ac5-a165-c0a11b4ca4dc
status: experimental
description: |
    Detects potential network activity of Weezo RMM tool
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
            - '*.weezo.me'
            - 'weezo.net'
            - '*.weezo.net'
            - 'weezo.en.softonic.com'
    condition: selection
falsepositives:
    - Legitimate use of Weezo
level: medium
```
