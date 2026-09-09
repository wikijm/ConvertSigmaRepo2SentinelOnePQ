```sql
// Translated content (automatically translated on 09-09-2026 02:01:10):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".teramind.co" or url.address contains "teramind.co" or url.address contains "www.teramind.co" or url.address contains "rt.teramind.co" or url.address contains "sentry.dev.teramind.co" or url.address contains "<on-prem-master-server-host>" or url.address contains "<on-prem-app-server-host>") or (event.dns.request contains ".teramind.co" or event.dns.request contains "teramind.co" or event.dns.request contains "www.teramind.co" or event.dns.request contains "rt.teramind.co" or event.dns.request contains "sentry.dev.teramind.co" or event.dns.request contains "<on-prem-master-server-host>" or event.dns.request contains "<on-prem-app-server-host>")))
```


# Original Sigma Rule:
```yaml
title: Potential Teramind RMM Tool Network Activity
id: 6eeb9f4e-b360-5446-8544-aea7b7e0721e
status: experimental
description: |
    Detects potential network activity of Teramind RMM tool
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
            - '*.teramind.co'
            - 'teramind.co'
            - 'www.teramind.co'
            - 'rt.teramind.co'
            - 'sentry.dev.teramind.co'
            - '<on-prem-master-server-host>'
            - '<on-prem-app-server-host>'
    condition: selection
falsepositives:
    - Legitimate use of Teramind
level: medium
```
