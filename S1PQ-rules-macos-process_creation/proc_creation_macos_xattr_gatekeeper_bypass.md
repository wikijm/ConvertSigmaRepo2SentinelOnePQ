```sql
// Translated content (automatically translated on 22-12-2025 01:26:43):
event.type="Process Creation" and (endpoint.os="osx" and (tgt.process.image.path contains "/xattr" and (tgt.process.cmdline contains "-d" and tgt.process.cmdline contains "com.apple.quarantine")))
```


# Original Sigma Rule:
```yaml
title: Gatekeeper Bypass via Xattr
id: f5141b6d-9f42-41c6-a7bf-2a780678b29b
status: test
description: Detects macOS Gatekeeper bypass via xattr utility
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/1fed40dc7e48f16ed44dcdd9c73b9222a70cca85/atomics/T1553.001/T1553.001.md
    - https://www.loobins.io/binaries/xattr/
author: Daniil Yugoslavskiy, oscd.community
date: 2020-10-19
modified: 2024-04-18
tags:
    - attack.defense-evasion
    - attack.t1553.001
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        Image|endswith: '/xattr'
        CommandLine|contains|all:
            - '-d'
            - 'com.apple.quarantine'
    condition: selection
falsepositives:
    - Legitimate activities
level: low
```
