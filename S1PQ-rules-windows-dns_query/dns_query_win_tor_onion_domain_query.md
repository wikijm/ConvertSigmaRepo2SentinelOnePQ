```sql
// Translated content (automatically translated on 02-08-2025 02:10:48):
event.category="DNS" and (endpoint.os="windows" and event.dns.request contains ".onion")
```


# Original Sigma Rule:
```yaml
title: DNS Query Tor .Onion Address - Sysmon
id: b55ca2a3-7cff-4dda-8bdd-c7bfa63bf544
related:
    - id: 8384bd26-bde6-4da9-8e5d-4174a7a47ca2
      type: similar
status: test
description: Detects DNS queries to an ".onion" address related to Tor routing networks
references:
    - https://www.logpoint.com/en/blog/detecting-tor-use-with-logpoint/
author: frack113
date: 2022-02-20
modified: 2023-09-18
tags:
    - attack.command-and-control
    - attack.t1090.003
logsource:
    product: windows
    category: dns_query
detection:
    selection:
        QueryName|contains: '.onion'
    condition: selection
falsepositives:
    - Unknown
level: high
```
