```sql
// Translated content (automatically translated on 30-11-2025 00:59:06):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".ninjarmm.com" or url.address contains ".ninjaone.com" or url.address contains "resources.ninjarmm.com" or url.address contains "ninjaone.com" or url.address contains "ninjarmm.net" or url.address contains ".ninjarmm.net" or url.address contains "rmmservice.eu" or url.address contains ".rmmservice.eu" or url.address contains "rmmservice.eu" or url.address contains ".rmmservice.eu" or url.address contains "rmmservice.com.au" or url.address contains ".rmmservice.com.au" or url.address contains "rmmservice.ca" or url.address contains ".rmmservice.ca" or url.address contains "ninja-backup.com" or url.address contains ".ninja-backup.com") or (event.dns.request contains ".ninjarmm.com" or event.dns.request contains ".ninjaone.com" or event.dns.request contains "resources.ninjarmm.com" or event.dns.request contains "ninjaone.com" or event.dns.request contains "ninjarmm.net" or event.dns.request contains ".ninjarmm.net" or event.dns.request contains "rmmservice.eu" or event.dns.request contains ".rmmservice.eu" or event.dns.request contains "rmmservice.eu" or event.dns.request contains ".rmmservice.eu" or event.dns.request contains "rmmservice.com.au" or event.dns.request contains ".rmmservice.com.au" or event.dns.request contains "rmmservice.ca" or event.dns.request contains ".rmmservice.ca" or event.dns.request contains "ninja-backup.com" or event.dns.request contains ".ninja-backup.com")))
```


# Original Sigma Rule:
```yaml
title: Potential NinjaRMM RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - '*.ninjarmm.com'
    - '*.ninjaone.com'
    - resources.ninjarmm.com
    - ninjaone.com
    - ninjarmm.net
    - '*.ninjarmm.net'
    - rmmservice.eu
    - '*.rmmservice.eu'
    - rmmservice.eu
    - '*.rmmservice.eu'
    - rmmservice.com.au
    - '*.rmmservice.com.au'
    - rmmservice.ca
    - '*.rmmservice.ca'
    - ninja-backup.com
    - '*.ninja-backup.com'
  condition: selection
id: 36fd47e6-13f9-4eb0-a826-8f34e3e1dc0e
status: experimental
description: Detects potential network activity of NinjaRMM RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of NinjaRMM
level: medium
```
