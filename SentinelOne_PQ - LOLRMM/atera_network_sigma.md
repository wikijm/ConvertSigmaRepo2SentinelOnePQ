```sql
// Translated content (automatically translated on 02-08-2025 00:55:07):
(event.category in ("DNS","Url","IP")) and (endpoint.os="windows" and ((url.address contains "pubsub.atera.com" or url.address contains "pubsub.pubnub.com" or url.address contains "agentreporting.atera.com" or url.address contains "getalphacontrol.com" or url.address contains "app.atera.com" or url.address contains "agenthb.atera.com" or url.address contains "packagesstore.blob.core.windows.net" or url.address contains "ps.pndsn.com" or url.address contains "agent-api.atera.com" or url.address contains "cacerts.thawte.com" or url.address contains "agentreportingstore.blob.core.windows.net" or url.address contains "atera-agent-heartbeat.servicebus.windows.net" or url.address contains "ps.atera.com" or url.address contains "atera.pubnubapi.com" or url.address contains "appcdn.atera.com") or (event.dns.request contains "pubsub.atera.com" or event.dns.request contains "pubsub.pubnub.com" or event.dns.request contains "agentreporting.atera.com" or event.dns.request contains "getalphacontrol.com" or event.dns.request contains "app.atera.com" or event.dns.request contains "agenthb.atera.com" or event.dns.request contains "packagesstore.blob.core.windows.net" or event.dns.request contains "ps.pndsn.com" or event.dns.request contains "agent-api.atera.com" or event.dns.request contains "cacerts.thawte.com" or event.dns.request contains "agentreportingstore.blob.core.windows.net" or event.dns.request contains "atera-agent-heartbeat.servicebus.windows.net" or event.dns.request contains "ps.atera.com" or event.dns.request contains "atera.pubnubapi.com" or event.dns.request contains "appcdn.atera.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Atera RMM Tool Network Activity
logsource:
  product: windows
  category: network_connection
detection:
  selection:
    DestinationHostname|endswith:
    - pubsub.atera.com
    - pubsub.pubnub.com
    - agentreporting.atera.com
    - getalphacontrol.com
    - app.atera.com
    - agenthb.atera.com
    - packagesstore.blob.core.windows.net
    - ps.pndsn.com
    - agent-api.atera.com
    - cacerts.thawte.com
    - agentreportingstore.blob.core.windows.net
    - atera-agent-heartbeat.servicebus.windows.net
    - ps.atera.com
    - atera.pubnubapi.com
    - appcdn.atera.com
  condition: selection
id: ea23aeb1-701b-4cd9-9951-5d00ce194c2b
status: experimental
description: Detects potential network activity of Atera RMM tool
author: LOLRMM Project
date: 2024/08/07
tags:
- attack.execution
- attack.t1219
falsepositives:
- Legitimate use of Atera
level: medium
```
