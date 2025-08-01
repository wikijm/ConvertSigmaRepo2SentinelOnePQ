```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "--remote-debugging-" and tgt.process.cmdline contains "--user-data-dir" and tgt.process.cmdline contains "--headless"))
```


# Original Sigma Rule:
```yaml
title: Potential Data Stealing Via Chromium Headless Debugging
id: 3e8207c5-fcd2-4ea6-9418-15d45b4890e4
related:
    - id: b3d34dc5-2efd-4ae3-845f-8ec14921f449
      type: derived
status: test
description: Detects chromium based browsers starting in headless and debugging mode and pointing to a user profile. This could be a sign of data stealing or remote control
references:
    - https://github.com/defaultnamehere/cookie_crimes/
    - https://mango.pdf.zone/stealing-chrome-cookies-without-a-password
    - https://embracethered.com/blog/posts/2020/cookie-crimes-on-mirosoft-edge/
    - https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-12-23
tags:
    - attack.credential-access
    - attack.collection
    - attack.t1185
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - '--remote-debugging-' # Covers: --remote-debugging-address, --remote-debugging-port, --remote-debugging-socket-name, --remote-debugging-pipe....etc
            - '--user-data-dir'
            - '--headless'
    condition: selection
falsepositives:
    - Unknown
level: high
```
