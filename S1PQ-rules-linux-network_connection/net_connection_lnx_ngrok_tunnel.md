```sql
// Translated content (automatically translated on 22-12-2025 01:41:54):
(event.category in ("dns","url","ip")) and (endpoint.os="linux" and ((url.address contains "tunnel.us.ngrok.com" or url.address contains "tunnel.eu.ngrok.com" or url.address contains "tunnel.ap.ngrok.com" or url.address contains "tunnel.au.ngrok.com" or url.address contains "tunnel.sa.ngrok.com" or url.address contains "tunnel.jp.ngrok.com" or url.address contains "tunnel.in.ngrok.com") or (event.dns.request contains "tunnel.us.ngrok.com" or event.dns.request contains "tunnel.eu.ngrok.com" or event.dns.request contains "tunnel.ap.ngrok.com" or event.dns.request contains "tunnel.au.ngrok.com" or event.dns.request contains "tunnel.sa.ngrok.com" or event.dns.request contains "tunnel.jp.ngrok.com" or event.dns.request contains "tunnel.in.ngrok.com")))
```


# Original Sigma Rule:
```yaml
title: Communication To Ngrok Tunneling Service - Linux
id: 19bf6fdb-7721-4f3d-867f-53467f6a5db6
status: test
description: Detects an executable accessing an ngrok tunneling endpoint, which could be a sign of forbidden exfiltration of data exfiltration by malicious actors
references:
    - https://twitter.com/hakluke/status/1587733971814977537/photo/1
    - https://ngrok.com/docs/secure-tunnels/tunnels/ssh-reverse-tunnel-agent
author: Florian Roth (Nextron Systems)
date: 2022-11-03
tags:
    - attack.exfiltration
    - attack.command-and-control
    - attack.t1567
    - attack.t1568.002
    - attack.t1572
    - attack.t1090
    - attack.t1102
    - attack.s0508
logsource:
    product: linux
    category: network_connection
detection:
    selection:
        DestinationHostname|contains:
            - 'tunnel.us.ngrok.com'
            - 'tunnel.eu.ngrok.com'
            - 'tunnel.ap.ngrok.com'
            - 'tunnel.au.ngrok.com'
            - 'tunnel.sa.ngrok.com'
            - 'tunnel.jp.ngrok.com'
            - 'tunnel.in.ngrok.com'
    condition: selection
falsepositives:
    - Legitimate use of ngrok
level: high
```
