```sql
// Translated content (automatically translated on 02-08-2025 00:59:06):
event.type="Process Creation" and (endpoint.os="linux" and (tgt.process.image.path contains "/uname" or tgt.process.image.path contains "/hostname" or tgt.process.image.path contains "/uptime" or tgt.process.image.path contains "/lspci" or tgt.process.image.path contains "/dmidecode" or tgt.process.image.path contains "/lscpu" or tgt.process.image.path contains "/lsmod"))
```


# Original Sigma Rule:
```yaml
title: System Information Discovery
id: 42df45e7-e6e9-43b5-8f26-bec5b39cc239
status: stable
description: Detects system information discovery commands
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1082/T1082.md
author: Ömer Günal, oscd.community
date: 2020-10-08
modified: 2021-09-14
tags:
    - attack.discovery
    - attack.t1082
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|endswith:
            - '/uname'
            - '/hostname'
            - '/uptime'
            - '/lspci'
            - '/dmidecode'
            - '/lscpu'
            - '/lsmod'
    condition: selection
falsepositives:
    - Legitimate administration activities
level: informational
```
