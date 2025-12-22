```sql
// Translated content (automatically translated on 22-12-2025 01:26:43):
event.type="Process Creation" and (endpoint.os="osx" and ((tgt.process.image.path contains "/tmutil" or tgt.process.cmdline contains "tmutil") and tgt.process.cmdline contains "disable"))
```


# Original Sigma Rule:
```yaml
title: Time Machine Backup Disabled Via Tmutil - MacOS
id: 2c95fa8a-8b8d-4787-afce-7117ceb8e3da
status: test
description: |
    Detects disabling of Time Machine (Apple's automated backup utility software) via the native macOS backup utility "tmutil".
    An attacker can use this to prevent backups from occurring.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1490/T1490.md#atomic-test-12---disable-time-machine
    - https://www.loobins.io/binaries/tmutil/
author: Pratinav Chandra
date: 2024-05-29
tags:
    - attack.impact
    - attack.t1490
logsource:
    category: process_creation
    product: macos
detection:
    selection_img:
        - Image|endswith: '/tmutil'
        - CommandLine|contains: 'tmutil'
    selection_cmd:
        CommandLine|contains: 'disable'
    condition: all of selection_*
falsepositives:
    - Legitimate administrator activity
level: medium
```
