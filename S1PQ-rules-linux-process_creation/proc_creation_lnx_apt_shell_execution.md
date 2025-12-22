```sql
// Translated content (automatically translated on 22-12-2025 01:02:22):
event.type="Process Creation" and (endpoint.os="linux" and ((tgt.process.image.path contains "/apt" or tgt.process.image.path contains "/apt-get") and tgt.process.cmdline contains "APT::Update::Pre-Invoke::="))
```


# Original Sigma Rule:
```yaml
title: Shell Invocation via Apt - Linux
id: bb382fd5-b454-47ea-a264-1828e4c766d6
status: test
description: |
    Detects the use of the "apt" and "apt-get" commands to execute a shell or proxy commands.
    Such behavior may be associated with privilege escalation, unauthorized command execution, or to break out from restricted environments.
references:
    - https://gtfobins.github.io/gtfobins/apt/
    - https://gtfobins.github.io/gtfobins/apt-get/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-12-28
modified: 2024-09-02
tags:
    - attack.discovery
    - attack.t1083
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith:
            - '/apt'
            - '/apt-get'
        CommandLine|contains: 'APT::Update::Pre-Invoke::='
    condition: selection
falsepositives:
    - Unknown
level: medium
```
