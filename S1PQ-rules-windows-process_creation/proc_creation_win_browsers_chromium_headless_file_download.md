```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\brave.exe" or tgt.process.image.path contains "\chrome.exe" or tgt.process.image.path contains "\msedge.exe" or tgt.process.image.path contains "\opera.exe" or tgt.process.image.path contains "\vivaldi.exe") and (tgt.process.cmdline contains "--headless" and tgt.process.cmdline contains "dump-dom" and tgt.process.cmdline contains "http")))
```


# Original Sigma Rule:
```yaml
title: File Download with Headless Browser
id: 0e8cfe08-02c9-4815-a2f8-0d157b7ed33e
related:
    - id: ef9dcfed-690c-4c5d-a9d1-482cd422225c
      type: derived
status: test
description: Detects execution of chromium based browser in headless mode using the "dump-dom" command line to download files
references:
    - https://twitter.com/mrd0x/status/1478234484881436672?s=12
    - https://www.trendmicro.com/en_us/research/23/e/managed-xdr-investigation-of-ducktail-in-trend-micro-vision-one.html
author: Sreeman, Florian Roth (Nextron Systems)
date: 2022-01-04
modified: 2023-05-12
tags:
    - attack.command-and-control
    - attack.t1105
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
        CommandLine|contains|all:
            - '--headless'
            - 'dump-dom'
            - 'http'
    condition: selection
falsepositives:
    - Unknown
level: high
```
