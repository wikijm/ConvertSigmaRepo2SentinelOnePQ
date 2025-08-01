```sql
// Translated content (automatically translated on 02-08-2025 01:37:22):
(event.category in ("DNS","Url","IP")) and (endpoint.os="linux" and ((url.address in ("pool.minexmr.com","fr.minexmr.com","de.minexmr.com","sg.minexmr.com","ca.minexmr.com","us-west.minexmr.com","pool.supportxmr.com","mine.c3pool.com","xmr-eu1.nanopool.org","xmr-eu2.nanopool.org","xmr-us-east1.nanopool.org","xmr-us-west1.nanopool.org","xmr-asia1.nanopool.org","xmr-jp1.nanopool.org","xmr-au1.nanopool.org","xmr.2miners.com","xmr.hashcity.org","xmr.f2pool.com","xmrpool.eu","pool.hashvault.pro","moneroocean.stream","monerocean.stream")) or (event.dns.request in ("pool.minexmr.com","fr.minexmr.com","de.minexmr.com","sg.minexmr.com","ca.minexmr.com","us-west.minexmr.com","pool.supportxmr.com","mine.c3pool.com","xmr-eu1.nanopool.org","xmr-eu2.nanopool.org","xmr-us-east1.nanopool.org","xmr-us-west1.nanopool.org","xmr-asia1.nanopool.org","xmr-jp1.nanopool.org","xmr-au1.nanopool.org","xmr.2miners.com","xmr.hashcity.org","xmr.f2pool.com","xmrpool.eu","pool.hashvault.pro","moneroocean.stream","monerocean.stream"))))
```


# Original Sigma Rule:
```yaml
title: Linux Crypto Mining Pool Connections
id: a46c93b7-55ed-4d27-a41b-c259456c4746
status: stable
description: Detects process connections to a Monero crypto mining pool
references:
    - https://www.poolwatch.io/coin/monero
author: Florian Roth (Nextron Systems)
date: 2021-10-26
tags:
    - attack.impact
    - attack.t1496
logsource:
    product: linux
    category: network_connection
detection:
    selection:
        DestinationHostname:
            - 'pool.minexmr.com'
            - 'fr.minexmr.com'
            - 'de.minexmr.com'
            - 'sg.minexmr.com'
            - 'ca.minexmr.com'
            - 'us-west.minexmr.com'
            - 'pool.supportxmr.com'
            - 'mine.c3pool.com'
            - 'xmr-eu1.nanopool.org'
            - 'xmr-eu2.nanopool.org'
            - 'xmr-us-east1.nanopool.org'
            - 'xmr-us-west1.nanopool.org'
            - 'xmr-asia1.nanopool.org'
            - 'xmr-jp1.nanopool.org'
            - 'xmr-au1.nanopool.org'
            - 'xmr.2miners.com'
            - 'xmr.hashcity.org'
            - 'xmr.f2pool.com'
            - 'xmrpool.eu'
            - 'pool.hashvault.pro'
            - 'moneroocean.stream'
            - 'monerocean.stream'
    condition: selection
falsepositives:
    - Legitimate use of crypto miners
level: high
```
