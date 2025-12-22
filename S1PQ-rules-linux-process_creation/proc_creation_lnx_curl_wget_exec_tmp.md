```sql
// Translated content (automatically translated on 22-12-2025 01:02:22):
event.type="Process Creation" and (endpoint.os="linux" and ((tgt.process.cmdline contains "/curl" or tgt.process.cmdline contains "/wget") and (tgt.process.cmdline contains "/tmp/" or tgt.process.cmdline contains "/dev/shm/") and tgt.process.cmdline contains "sh -c"))
```


# Original Sigma Rule:
```yaml
title: Suspicious Download and Execute Pattern via Curl/Wget
id: a2d9e2f3-0f43-4c7a-bcd9-9acfc0d723aa
status: experimental
description: |
    Detects suspicious use of command-line tools such as curl or wget to download remote
    content - particularly scripts - into temporary directories (e.g., /dev/shm, /tmp), followed by
    immediate execution, indicating potential malicious activity. This pattern is commonly used
    by malicious scripts, stagers, or downloaders in fileless or multi-stage Linux attacks.
references:
    - https://gtfobins.github.io/gtfobins/wget/
    - https://gtfobins.github.io/gtfobins/curl/
author: Aayush Gupta
date: 2025-06-17
tags:
    - attack.execution
    - attack.t1059.004
    - attack.t1203
logsource:
    category: process_creation
    product: linux
detection:
    selection_downloader:
        CommandLine|contains:
            - '/curl'
            - '/wget'
    selection_tmp:
        CommandLine|contains:
            - '/tmp/'
            - '/dev/shm/'
    selection_executor:
        CommandLine|contains: 'sh -c'
    condition: all of selection_*
falsepositives:
    - System update scripts using temporary files
    - Installer scripts or automated provisioning tools
level: high
```
