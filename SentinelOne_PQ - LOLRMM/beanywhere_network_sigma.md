```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "beanywhere.en.uptodown.com/windows" or url.address contains "beanywhere.com") or (event.dns.request contains "beanywhere.en.uptodown.com/windows" or event.dns.request contains "beanywhere.com")))
```


# Original Sigma Rule:
```yaml
title: Potential BeAnyWhere RMM Tool Network Activity
id: e68427eb-6abc-4dbe-85b9-0ca93e3742ed
status: experimental
description: |
    Detects potential network activity of BeAnyWhere RMM tool
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
            - beanywhere.en.uptodown.com/windows
            - beanywhere.com
    condition: selection
falsepositives:
    - Legitimate use of BeAnyWhere
level: medium
```
