```sql
// Translated content (automatically translated on 22-12-2025 01:26:43):
event.type="Process Creation" and (endpoint.os="osx" and ((tgt.process.image.path contains "/tmutil" or tgt.process.cmdline contains "tmutil") and tgt.process.cmdline contains "addexclusion"))
```


# Original Sigma Rule:
```yaml
title: New File Exclusion Added To Time Machine Via Tmutil - MacOS
id: 9acf45ed-3a26-4062-bf08-56857613eb52
status: test
description: |
    Detects the addition of a new file or path exclusion to MacOS Time Machine via the "tmutil" utility.
    An adversary could exclude a path from Time Machine backups to prevent certain files from being backed up.
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
        CommandLine|contains: 'addexclusion'
    condition: all of selection_*
falsepositives:
    - Legitimate administrator activity
level: medium
```
