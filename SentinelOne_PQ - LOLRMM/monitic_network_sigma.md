```sql
// Translated content (automatically translated on 09-09-2026 02:01:10):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "api.monitic.com" or url.address contains "app.monitic.com" or url.address contains "devapi.monitic.com" or url.address contains "turn.monitic.com" or url.address contains "monitic.com" or url.address contains "www.monitic.com") or (event.dns.request contains "api.monitic.com" or event.dns.request contains "app.monitic.com" or event.dns.request contains "devapi.monitic.com" or event.dns.request contains "turn.monitic.com" or event.dns.request contains "monitic.com" or event.dns.request contains "www.monitic.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Monitic RMM Tool Network Activity
id: b501b62b-dad9-576d-b87e-392af0623365
status: experimental
description: |
    Detects potential network activity of Monitic RMM tool
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
            - 'api.monitic.com'
            - 'app.monitic.com'
            - 'devapi.monitic.com'
            - 'turn.monitic.com'
            - 'monitic.com'
            - 'www.monitic.com'
    condition: selection
falsepositives:
    - Legitimate use of Monitic
level: medium
```
