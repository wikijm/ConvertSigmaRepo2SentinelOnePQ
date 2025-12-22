```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "user_managed" or url.address contains "simple-help.com" or url.address contains "51.255.19.178" or url.address contains "51.255.19.179") or (event.dns.request contains "user_managed" or event.dns.request contains "simple-help.com" or event.dns.request contains "51.255.19.178" or event.dns.request contains "51.255.19.179")))
```


# Original Sigma Rule:
```yaml
title: Potential SimpleHelp RMM Tool Network Activity
id: 5664ef88-4683-4f3c-9147-506eb5416d5e
status: experimental
description: |
    Detects potential network activity of SimpleHelp RMM tool
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
            - simple-help.com
            - 51.255.19.178
            - 51.255.19.179
    condition: selection
falsepositives:
    - Legitimate use of SimpleHelp
level: medium
```
