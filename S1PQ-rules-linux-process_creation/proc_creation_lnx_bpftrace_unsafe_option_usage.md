```sql
// Translated content (automatically translated on 22-12-2025 01:02:22):
event.type="Process Creation" and (endpoint.os="linux" and (tgt.process.image.path contains "bpftrace" and tgt.process.cmdline contains "--unsafe"))
```


# Original Sigma Rule:
```yaml
title: BPFtrace Unsafe Option Usage
id: f8341cb2-ee25-43fa-a975-d8a5a9714b39
status: test
description: Detects the usage of the unsafe bpftrace option
references:
    - https://embracethered.com/blog/posts/2021/offensive-bpf-bpftrace/
    - https://bpftrace.org/
author: Andreas Hunkeler (@Karneades)
date: 2022-02-11
tags:
    - attack.execution
    - attack.t1059.004
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: 'bpftrace'
        CommandLine|contains: '--unsafe'
    condition: selection
falsepositives:
    - Legitimate usage of the unsafe option
level: medium
```
