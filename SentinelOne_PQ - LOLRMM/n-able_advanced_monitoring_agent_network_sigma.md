```sql
// Translated content (automatically translated on 30-11-2025 00:59:06):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".beanywhere.com " or url.address contains "systemmonitor.co.uk" or url.address contains "system-monitor.com" or url.address contains "cloudbackup.management" or url.address contains "systemmonitor.co.uk" or url.address contains "n-able.com" or url.address contains "systemmonitor.us" or url.address contains "systemmonitor.eu.com" or url.address contains ".logicnow.com" or url.address contains ".swi-tc.com" or url.address contains "remote.management" or url.address contains "systemmonitor.us.cdn.cloudflare.net" or url.address contains "cloudbackup.management" or url.address contains "remote.management" or url.address contains "logicnow.com" or url.address contains "system-monitor.com" or url.address contains "systemmonitor.us" or url.address contains "systemmonitor.eu.com" or url.address contains ".n-able.com") or (event.dns.request contains ".beanywhere.com " or event.dns.request contains "systemmonitor.co.uk" or event.dns.request contains "system-monitor.com" or event.dns.request contains "cloudbackup.management" or event.dns.request contains "systemmonitor.co.uk" or event.dns.request contains "n-able.com" or event.dns.request contains "systemmonitor.us" or event.dns.request contains "systemmonitor.eu.com" or event.dns.request contains ".logicnow.com" or event.dns.request contains ".swi-tc.com" or event.dns.request contains "remote.management" or event.dns.request contains "systemmonitor.us.cdn.cloudflare.net" or event.dns.request contains "cloudbackup.management" or event.dns.request contains "remote.management" or event.dns.request contains "logicnow.com" or event.dns.request contains "system-monitor.com" or event.dns.request contains "systemmonitor.us" or event.dns.request contains "systemmonitor.eu.com" or event.dns.request contains ".n-able.com")))
```


# Original Sigma Rule:
```yaml
title: Potential N-Able Advanced Monitoring Agent RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.beanywhere.com '
    - systemmonitor.co.uk
    - '*system-monitor.com'
    - cloudbackup.management
    - '*systemmonitor.co.uk'
    - n-able.com
    - systemmonitor.us
    - '*systemmonitor.eu.com'
    - '*.logicnow.com'
    - '*.swi-tc.com'
    - '*remote.management'
    - systemmonitor.us.cdn.cloudflare.net
    - '*cloudbackup.management'
    - remote.management
    - logicnow.com
    - system-monitor.com
    - '*systemmonitor.us'
    - systemmonitor.eu.com
    - '*.n-able.com'
  condition: selection
id: ca8791dc-7469-4a02-945f-80b9a131b0c4
status: experimental
description: Detects potential network activity of N-Able Advanced Monitoring Agent
  RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of N-Able Advanced Monitoring Agent
level: medium
```
