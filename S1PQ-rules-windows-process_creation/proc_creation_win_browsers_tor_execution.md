```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\tor.exe" or tgt.process.image.path contains "\Tor Browser\Browser\firefox.exe"))
```


# Original Sigma Rule:
```yaml
title: Tor Client/Browser Execution
id: 62f7c9bf-9135-49b2-8aeb-1e54a6ecc13c
status: test
description: Detects the use of Tor or Tor-Browser to connect to onion routing networks
references:
    - https://www.logpoint.com/en/blog/detecting-tor-use-with-logpoint/
author: frack113
date: 2022-02-20
modified: 2023-02-13
tags:
    - attack.command-and-control
    - attack.t1090.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\tor.exe'
            - '\Tor Browser\Browser\firefox.exe'
    condition: selection
falsepositives:
    - Unknown
level: high
```
