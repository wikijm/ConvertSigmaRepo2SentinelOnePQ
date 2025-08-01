```sql
// Translated content (automatically translated on 02-08-2025 00:59:06):
event.type="Process Creation" and (endpoint.os="linux" and (tgt.process.image.path contains "/sudo" and tgt.process.cmdline contains "execve_hijack"))
```


# Original Sigma Rule:
```yaml
title: Triple Cross eBPF Rootkit Execve Hijack
id: 0326c3c8-7803-4a0f-8c5c-368f747f7c3e
status: test
description: Detects execution of a the file "execve_hijack" which is used by the Triple Cross rootkit as a way to elevate privileges
references:
    - https://github.com/h3xduck/TripleCross/blob/1f1c3e0958af8ad9f6ebe10ab442e75de33e91de/src/helpers/execve_hijack.c#L275
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-07-05
tags:
    - attack.defense-evasion
    - attack.privilege-escalation
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: '/sudo'
        CommandLine|contains: 'execve_hijack'
    condition: selection
falsepositives:
    - Unlikely
level: high
```
