```sql
// Translated content (automatically translated on 02-08-2025 02:10:48):
event.category="DNS" and (endpoint.os="windows" and event.dns.request contains ".anonfiles.com")
```


# Original Sigma Rule:
```yaml
title: DNS Query for Anonfiles.com Domain - Sysmon
id: 065cceea-77ec-4030-9052-fc0affea7110
related:
    - id: 29f171d7-aa47-42c7-9c7b-3c87938164d9
      type: similar
status: test
description: Detects DNS queries for "anonfiles.com", which is an anonymous file upload platform often used for malicious purposes
references:
    - https://www.trendmicro.com/vinfo/us/security/news/ransomware-spotlight/ransomware-spotlight-blackbyte
author: pH-T (Nextron Systems)
date: 2022-07-15
modified: 2023-01-16
tags:
    - attack.exfiltration
    - attack.t1567.002
logsource:
    product: windows
    category: dns_query
detection:
    selection:
        QueryName|contains: '.anonfiles.com'
    condition: selection
falsepositives:
    - Rare legitimate access to anonfiles.com
level: high
```
