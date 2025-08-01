```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and tgt.process.cmdline contains "\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths")
```


# Original Sigma Rule:
```yaml
title: Persistence Via TypedPaths - CommandLine
id: ec88289a-7e1a-4cc3-8d18-bd1f60e4b9ba
status: test
description: Detects modification addition to the 'TypedPaths' key in the user or admin registry via the commandline. Which might indicate persistence attempt
references:
    - https://twitter.com/dez_/status/1560101453150257154
    - https://forensafe.com/blogs/typedpaths.html
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-08-22
tags:
    - attack.persistence
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: '\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
