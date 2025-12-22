```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\\brave.exe" or tgt.process.image.path contains "\\chrome.exe" or tgt.process.image.path contains "\\msedge.exe" or tgt.process.image.path contains "\\opera.exe" or tgt.process.image.path contains "\\vivaldi.exe") and tgt.process.cmdline contains "--headless"))
```


# Original Sigma Rule:
```yaml
title: Browser Execution In Headless Mode
id: ef9dcfed-690c-4c5d-a9d1-482cd422225c
related:
    - id: 0e8cfe08-02c9-4815-a2f8-0d157b7ed33e
      type: derived
status: test
description: Detects execution of Chromium based browser in headless mode
references:
    - https://twitter.com/mrd0x/status/1478234484881436672?s=12
    - https://www.trendmicro.com/en_us/research/23/e/managed-xdr-investigation-of-ducktail-in-trend-micro-vision-one.html
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-09-12
tags:
    - attack.defense-evasion
    - attack.command-and-control
    - attack.t1105
    - attack.t1564.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\brave.exe'
            - '\chrome.exe'
            - '\msedge.exe'
            - '\opera.exe'
            - '\vivaldi.exe'
        CommandLine|contains: '--headless'
    condition: selection
falsepositives:
    - Unknown
level: low
```
