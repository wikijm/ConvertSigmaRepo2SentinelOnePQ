```sql
// Translated content (automatically translated on 07-09-2026 01:44:50):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "user_managed" or url.address contains "github.com" or url.address contains "raw.githubusercontent.com" or url.address contains "nezha.wiki" or url.address contains "nezhahq.github.io" or url.address contains "c.mid.al" or url.address contains "gd.bj2.xyz" or url.address contains "rism.pages.dev") or (event.dns.request contains "user_managed" or event.dns.request contains "github.com" or event.dns.request contains "raw.githubusercontent.com" or event.dns.request contains "nezha.wiki" or event.dns.request contains "nezhahq.github.io" or event.dns.request contains "c.mid.al" or event.dns.request contains "gd.bj2.xyz" or event.dns.request contains "rism.pages.dev")))
```


# Original Sigma Rule:
```yaml
title: Potential Nezha RMM Tool Network Activity
id: 5168cedf-2e2a-5aa9-b7fb-d1dd915f1b16
status: experimental
description: |
    Detects potential network activity of Nezha RMM tool
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
            - 'user_managed'
            - 'github.com'
            - 'raw.githubusercontent.com'
            - 'nezha.wiki'
            - 'nezhahq.github.io'
            - 'c.mid.al'
            - 'gd.bj2.xyz'
            - 'rism.pages.dev'
    condition: selection
falsepositives:
    - Legitimate use of Nezha
level: medium
```
