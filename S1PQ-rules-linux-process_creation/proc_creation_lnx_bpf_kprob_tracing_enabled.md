```sql
// Translated content (automatically translated on 22-12-2025 01:02:22):
event.type="Process Creation" and (endpoint.os="linux" and ((tgt.process.cmdline contains "echo 1 >" and tgt.process.cmdline contains "/sys/kernel/debug/tracing/events/kprobes/") and (tgt.process.cmdline contains "/myprobe/enable" or tgt.process.cmdline contains "/myretprobe/enable")))
```


# Original Sigma Rule:
```yaml
title: Enable BPF Kprobes Tracing
id: 7692f583-bd30-4008-8615-75dab3f08a99
status: test
description: Detects common command used to enable bpf kprobes tracing
references:
    - https://embracethered.com/blog/posts/2021/offensive-bpf-bpftrace/
    - https://bpftrace.org/
    - https://www.kernel.org/doc/html/v5.0/trace/kprobetrace.html
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-01-25
tags:
    - attack.execution
    - attack.defense-evasion
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        CommandLine|contains|all:
            - 'echo 1 >'
            - '/sys/kernel/debug/tracing/events/kprobes/'
        CommandLine|contains:
            - '/myprobe/enable'
            - '/myretprobe/enable'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
