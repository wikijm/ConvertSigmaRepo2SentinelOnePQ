```sql
// Translated content (automatically translated on 22-12-2025 01:02:22):
event.type="Process Creation" and (endpoint.os="linux" and tgt.process.image.path contains "/curl")
```


# Original Sigma Rule:
```yaml
title: Curl Usage on Linux
id: ea34fb97-e2c4-4afb-810f-785e4459b194
status: test
description: Detects a curl process start on linux, which indicates a file download from a remote location or a simple web request to a remote server
references:
    - https://www.trendmicro.com/en_us/research/22/i/how-malicious-actors-abuse-native-linux-tools-in-their-attacks.html
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-09-15
tags:
    - attack.command-and-control
    - attack.t1105
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: '/curl'
    condition: selection
falsepositives:
    - Scripts created by developers and admins
    - Administrative activity
level: low
```
