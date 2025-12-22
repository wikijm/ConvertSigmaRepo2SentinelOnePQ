```sql
// Translated content (automatically translated on 22-12-2025 01:02:22):
event.type="Process Creation" and (endpoint.os="linux" and (tgt.process.image.path contains "/chmod" and (tgt.process.cmdline contains "/tmp/" or tgt.process.cmdline contains "/.Library/" or tgt.process.cmdline contains "/etc/" or tgt.process.cmdline contains "/opt/")))
```


# Original Sigma Rule:
```yaml
title: Chmod Suspicious Directory
id: 6419afd1-3742-47a5-a7e6-b50386cd15f8
status: test
description: Detects chmod targeting files in abnormal directory paths.
references:
    - https://www.intezer.com/blog/malware-analysis/new-backdoor-sysjoker/
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1222.002/T1222.002.md
author: 'Christopher Peacock @SecurePeacock, SCYTHE @scythe_io'
date: 2022-06-03
tags:
    - attack.defense-evasion
    - attack.t1222.002
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|endswith: '/chmod'
        CommandLine|contains:
            - '/tmp/'
            - '/.Library/'
            - '/etc/'
            - '/opt/'
    condition: selection
falsepositives:
    - Admin changing file permissions.
level: medium
```
