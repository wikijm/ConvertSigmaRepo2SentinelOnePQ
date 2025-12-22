```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains "pubsub.atera.com" or url.address contains "pubsub.pubnub.com" or url.address contains "agentreporting.atera.com" or url.address contains "getalphacontrol.com" or url.address contains "app.atera.com" or url.address contains "agenthb.atera.com" or url.address contains "packagesstore.blob.core.windows.net" or url.address contains "ps.pndsn.com" or url.address contains "agent-api.atera.com" or url.address contains "cacerts.thawte.com" or url.address contains "agentreportingstore.blob.core.windows.net" or url.address contains "atera-agent-heartbeat.servicebus.windows.net" or url.address contains "ps.atera.com" or url.address contains "atera.pubnubapi.com" or url.address contains "appcdn.atera.com") or (event.dns.request contains "pubsub.atera.com" or event.dns.request contains "pubsub.pubnub.com" or event.dns.request contains "agentreporting.atera.com" or event.dns.request contains "getalphacontrol.com" or event.dns.request contains "app.atera.com" or event.dns.request contains "agenthb.atera.com" or event.dns.request contains "packagesstore.blob.core.windows.net" or event.dns.request contains "ps.pndsn.com" or event.dns.request contains "agent-api.atera.com" or event.dns.request contains "cacerts.thawte.com" or event.dns.request contains "agentreportingstore.blob.core.windows.net" or event.dns.request contains "atera-agent-heartbeat.servicebus.windows.net" or event.dns.request contains "ps.atera.com" or event.dns.request contains "atera.pubnubapi.com" or event.dns.request contains "appcdn.atera.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Atera RMM Tool Network Activity
id: 674787f1-97f4-4b3f-ae3a-361e909e800d
status: experimental
description: |
    Detects potential network activity of Atera RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2025-12-01
tags:
    - attack.execution
    - attack.t1219
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
falsepositives:
    - Legitimate use of Atera
level: medium
```
