```sql
// Translated content (automatically translated on 22-12-2025 02:20:29):
event.category="dns" and (endpoint.os="windows" and ((event.dns.request contains "aaa.stage." or event.dns.request contains "post.1") or event.dns.request contains ".stage.123456."))
```


# Original Sigma Rule:
```yaml
title: Suspicious Cobalt Strike DNS Beaconing - Sysmon
id: f356a9c4-effd-4608-bbf8-408afd5cd006
related:
    - id: 0d18728b-f5bf-4381-9dcf-915539fff6c2
      type: similar
status: test
description: Detects a program that invoked suspicious DNS queries known from Cobalt Strike beacons
references:
    - https://www.icebrg.io/blog/footprints-of-fin7-tracking-actor-patterns
    - https://www.sekoia.io/en/hunting-and-detecting-cobalt-strike/
author: Florian Roth (Nextron Systems)
date: 2021-11-09
modified: 2023-01-16
tags:
    - attack.command-and-control
    - attack.t1071.004
logsource:
    product: windows
    category: dns_query
detection:
    selection1:
        QueryName|startswith:
            - 'aaa.stage.'
            - 'post.1'
    selection2:
        QueryName|contains: '.stage.123456.'
    condition: 1 of selection*
falsepositives:
    - Unknown
level: critical
```
