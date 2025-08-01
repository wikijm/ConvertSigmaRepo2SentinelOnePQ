```sql
// Translated content (automatically translated on 02-08-2025 02:10:48):
event.category="DNS" and (endpoint.os="windows" and event.dns.request contains "userstorage.mega.co.nz")
```


# Original Sigma Rule:
```yaml
title: DNS Query To MEGA Hosting Website
id: 613c03ba-0779-4a53-8a1f-47f914a4ded3
related:
    - id: 66474410-b883-415f-9f8d-75345a0a66a6
      type: similar
status: test
description: Detects DNS queries for subdomains related to MEGA sharing website
references:
    - https://research.nccgroup.com/2021/05/27/detecting-rclone-an-effective-tool-for-exfiltration/
author: Aaron Greetham (@beardofbinary) - NCC Group
date: 2021-05-26
modified: 2023-09-18
tags:
    - attack.exfiltration
    - attack.t1567.002
logsource:
    product: windows
    category: dns_query
detection:
    selection:
        QueryName|contains: 'userstorage.mega.co.nz'
    condition: selection
falsepositives:
    - Legitimate DNS queries and usage of Mega
level: medium
```
