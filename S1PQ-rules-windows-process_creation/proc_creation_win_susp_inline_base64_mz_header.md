```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "TVqQAAMAAAAEAAAA" or tgt.process.cmdline contains "TVpQAAIAAAAEAA8A" or tgt.process.cmdline contains "TVqAAAEAAAAEABAA" or tgt.process.cmdline contains "TVoAAAAAAAAAAAAA" or tgt.process.cmdline contains "TVpTAQEAAAAEAAAA"))
```


# Original Sigma Rule:
```yaml
title: Base64 MZ Header In CommandLine
id: 22e58743-4ac8-4a9f-bf19-00a0428d8c5f
status: test
description: Detects encoded base64 MZ header in the commandline
references:
    - https://thedfirreport.com/2022/07/11/select-xmrig-from-sqlserver/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-07-12
tags:
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'TVqQAAMAAAAEAAAA' # MZ..........
            - 'TVpQAAIAAAAEAA8A'
            - 'TVqAAAEAAAAEABAA'
            - 'TVoAAAAAAAAAAAAA'
            - 'TVpTAQEAAAAEAAAA'
    condition: selection
falsepositives:
    - Unlikely
level: high
```
