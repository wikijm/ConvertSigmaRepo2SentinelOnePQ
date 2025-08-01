```sql
// Translated content (automatically translated on 02-08-2025 02:10:48):
event.category="DNS" and (endpoint.os="windows" and (event.dns.request="update.onelaunch.com" and src.process.image.path contains "\OneLaunch.exe"))
```


# Original Sigma Rule:
```yaml
title: DNS Query Request To OneLaunch Update Service
id: df68f791-ad95-447f-a271-640a0dab9cf8
status: test
description: |
    Detects DNS query requests to "update.onelaunch.com". This domain is associated with the OneLaunch adware application.
    When the OneLaunch application is installed it will attempt to get updates from this domain.
references:
    - https://www.malwarebytes.com/blog/detections/pup-optional-onelaunch-silentcf
    - https://www.myantispyware.com/2020/12/14/how-to-uninstall-onelaunch-browser-removal-guide/
    - https://malware.guide/browser-hijacker/remove-onelaunch-virus/
author: Josh Nickels
date: 2024-02-26
tags:
    - attack.collection
    - attack.t1056
logsource:
    category: dns_query
    product: windows
detection:
    selection:
        QueryName: 'update.onelaunch.com'
        Image|endswith: '\OneLaunch.exe'
    condition: selection
falsepositives:
    - Unlikely
level: low
```
