```sql
// Translated content (automatically translated on 22-12-2025 02:20:29):
event.category="dns" and (endpoint.os="windows" and (event.dns.request contains ".v2.argotunnel.com" or event.dns.request contains "protocol-v2.argotunnel.com" or event.dns.request contains "trycloudflare.com" or event.dns.request contains "update.argotunnel.com"))
```


# Original Sigma Rule:
```yaml
title: Cloudflared Tunnels Related DNS Requests
id: a1d9eec5-33b2-4177-8d24-27fe754d0812
related:
    - id: 7cd1dcdc-6edf-4896-86dc-d1f19ad64903
      type: similar
status: test
description: |
    Detects DNS requests to Cloudflared tunnels domains.
    Attackers can abuse that feature to establish a reverse shell or persistence on a machine.
references:
    - https://www.guidepointsecurity.com/blog/tunnel-vision-cloudflared-abused-in-the-wild/
    - Internal Research
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-12-20
tags:
    - attack.command-and-control
    - attack.t1071.001
    - attack.t1572
logsource:
    category: dns_query
    product: windows
detection:
    selection:
        QueryName|endswith:
            - '.v2.argotunnel.com'
            - 'protocol-v2.argotunnel.com'
            - 'trycloudflare.com'
            - 'update.argotunnel.com'
    condition: selection
falsepositives:
    - Legitimate use of cloudflare tunnels will also trigger this.
level: medium
```
