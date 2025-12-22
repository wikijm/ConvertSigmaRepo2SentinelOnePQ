```sql
// Translated content (automatically translated on 22-12-2025 02:20:29):
event.category="dns" and (endpoint.os="windows" and (event.dns.request contains ".hiddenservice.net" or event.dns.request contains ".onion.ca" or event.dns.request contains ".onion.cab" or event.dns.request contains ".onion.casa" or event.dns.request contains ".onion.city" or event.dns.request contains ".onion.direct" or event.dns.request contains ".onion.dog" or event.dns.request contains ".onion.glass" or event.dns.request contains ".onion.gq" or event.dns.request contains ".onion.ink" or event.dns.request contains ".onion.it" or event.dns.request contains ".onion.link" or event.dns.request contains ".onion.lt" or event.dns.request contains ".onion.lu" or event.dns.request contains ".onion.nu" or event.dns.request contains ".onion.pet" or event.dns.request contains ".onion.plus" or event.dns.request contains ".onion.rip" or event.dns.request contains ".onion.sh" or event.dns.request contains ".onion.to" or event.dns.request contains ".onion.top" or event.dns.request contains ".onion" or event.dns.request contains ".s1.tor-gateways.de" or event.dns.request contains ".s2.tor-gateways.de" or event.dns.request contains ".s3.tor-gateways.de" or event.dns.request contains ".s4.tor-gateways.de" or event.dns.request contains ".s5.tor-gateways.de" or event.dns.request contains ".t2w.pw" or event.dns.request contains ".tor2web.ae.org" or event.dns.request contains ".tor2web.blutmagie.de" or event.dns.request contains ".tor2web.com" or event.dns.request contains ".tor2web.fi" or event.dns.request contains ".tor2web.io" or event.dns.request contains ".tor2web.org" or event.dns.request contains ".tor2web.xyz" or event.dns.request contains ".torlink.co"))
```


# Original Sigma Rule:
```yaml
title: DNS Query Tor .Onion Address - Sysmon
id: b55ca2a3-7cff-4dda-8bdd-c7bfa63bf544
related:
    - id: 8384bd26-bde6-4da9-8e5d-4174a7a47ca2
      type: similar
    - id: a8322756-015c-42e7-afb1-436e85ed3ff5
      type: similar
status: test
description: Detects DNS queries to an ".onion" address related to Tor routing networks
references:
    - https://www.logpoint.com/en/blog/detecting-tor-use-with-logpoint/
    - https://github.com/Azure/Azure-Sentinel/blob/f99542b94afe0ad2f19a82cc08262e7ac8e1428e/Detections/ASimDNS/imDNS_TorProxies.yaml
author: frack113
date: 2022-02-20
modified: 2025-09-12
tags:
    - attack.command-and-control
    - attack.t1090.003
logsource:
    product: windows
    category: dns_query
detection:
    selection:
        QueryName|endswith:
            - '.hiddenservice.net'
            - '.onion.ca'
            - '.onion.cab'
            - '.onion.casa'
            - '.onion.city'
            - '.onion.direct'
            - '.onion.dog'
            - '.onion.glass'
            - '.onion.gq'
            - '.onion.ink'
            - '.onion.it'
            - '.onion.link'
            - '.onion.lt'
            - '.onion.lu'
            - '.onion.nu'
            - '.onion.pet'
            - '.onion.plus'
            - '.onion.rip'
            - '.onion.sh'
            - '.onion.to'
            - '.onion.top'
            - '.onion'
            - '.s1.tor-gateways.de'
            - '.s2.tor-gateways.de'
            - '.s3.tor-gateways.de'
            - '.s4.tor-gateways.de'
            - '.s5.tor-gateways.de'
            - '.t2w.pw'
            - '.tor2web.ae.org'
            - '.tor2web.blutmagie.de'
            - '.tor2web.com'
            - '.tor2web.fi'
            - '.tor2web.io'
            - '.tor2web.org'
            - '.tor2web.xyz'
            - '.torlink.co'
    condition: selection
falsepositives:
    - Unknown
level: high
```
