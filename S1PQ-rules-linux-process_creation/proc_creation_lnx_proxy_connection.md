```sql
// Translated content (automatically translated on 22-12-2025 01:02:22):
event.type="Process Creation" and (endpoint.os="linux" and (tgt.process.cmdline contains "http_proxy=" or tgt.process.cmdline contains "https_proxy="))
```


# Original Sigma Rule:
```yaml
title: Connection Proxy
id: 72f4ab3f-787d-495d-a55d-68c2ff46cf4c
status: test
description: Detects setting proxy configuration
author: Ömer Günal
date: 2020-06-17
modified: 2022-10-05
tags:
    - attack.defense-evasion
    - attack.command-and-control
    - attack.t1090
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - 'http_proxy='
            - 'https_proxy='
    condition: selection
falsepositives:
    - Legitimate administration activities
level: low
```
