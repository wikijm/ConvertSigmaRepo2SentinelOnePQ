```sql
// Translated content (automatically translated on 02-08-2025 01:23:44):
event.type="Process Creation" and (endpoint.os="osx" and ((tgt.process.image.path contains "/tmutil" or tgt.process.cmdline contains "tmutil") and tgt.process.cmdline contains "delete"))
```


# Original Sigma Rule:
```yaml
title: Time Machine Backup Deletion Attempt Via Tmutil - MacOS
id: 452df256-da78-427a-866f-49fa04417d74
status: test
description: |
    Detects deletion attempts of MacOS Time Machine backups via the native backup utility "tmutil".
    An adversary may perform this action before launching a ransonware attack to prevent the victim from restoring their files.
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
        CommandLine|contains: 'delete'
    condition: all of selection_*
falsepositives:
    - Legitimate activities
level: medium
```
