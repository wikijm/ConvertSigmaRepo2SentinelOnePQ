```sql
// Translated content (automatically translated on 22-12-2025 01:02:22):
event.type="Process Creation" and (endpoint.os="linux" and (tgt.process.image.path contains "/find" and (tgt.process.cmdline contains "-perm -4000" or tgt.process.cmdline contains "-perm -2000" or tgt.process.cmdline contains "-perm 0777" or tgt.process.cmdline contains "-perm -222" or tgt.process.cmdline contains "-perm -o w" or tgt.process.cmdline contains "-perm -o x" or tgt.process.cmdline contains "-perm -u=s" or tgt.process.cmdline contains "-perm -g=s")))
```


# Original Sigma Rule:
```yaml
title: Potential Discovery Activity Using Find - Linux
id: 8344c0e5-5783-47cc-9cf9-a0f7fd03e6cf
related:
    - id: 85de3a19-b675-4a51-bfc6-b11a5186c971
      type: similar
status: test
description: Detects usage of "find" binary in a suspicious manner to perform discovery
references:
    - https://github.com/SaiSathvik1/Linux-Privilege-Escalation-Notes
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-12-28
tags:
    - attack.discovery
    - attack.t1083
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: '/find'
        CommandLine|contains:
            - '-perm -4000'
            - '-perm -2000'
            - '-perm 0777'
            - '-perm -222'
            - '-perm -o w'
            - '-perm -o x'
            - '-perm -u=s'
            - '-perm -g=s'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
