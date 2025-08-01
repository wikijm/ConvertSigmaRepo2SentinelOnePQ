```sql
// Translated content (automatically translated on 02-08-2025 02:10:48):
event.category="DNS" and (endpoint.os="windows" and (event.dns.request contains "servicebus.windows.net" and src.process.image.path contains "HybridConnectionManager"))
```


# Original Sigma Rule:
```yaml
title: DNS HybridConnectionManager Service Bus
id: 7bd3902d-8b8b-4dd4-838a-c6862d40150d
status: test
description: Detects Azure Hybrid Connection Manager services querying the Azure service bus service
references:
    - https://twitter.com/Cyb3rWard0g/status/1381642789369286662
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
date: 2021-04-12
modified: 2023-01-16
tags:
    - attack.persistence
    - attack.t1554
logsource:
    product: windows
    category: dns_query
detection:
    selection:
        QueryName|contains: 'servicebus.windows.net'
        Image|contains: 'HybridConnectionManager'
    condition: selection
falsepositives:
    - Legitimate use of Azure Hybrid Connection Manager and the Azure Service Bus service
level: high
```
