```sql
// Translated content (automatically translated on 22-12-2025 01:26:43):
event.type="Process Creation" and (endpoint.os="osx" and (tgt.process.cmdline contains " " or tgt.process.image.path contains " "))
```


# Original Sigma Rule:
```yaml
title: Space After Filename - macOS
id: b6e2a2e3-2d30-43b1-a4ea-071e36595690
status: test
description: Detects attempts to masquerade as legitimate files by adding a space to the end of the filename.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1036.006/T1036.006.md
author: remotephone
date: 2021-11-20
modified: 2023-01-04
tags:
    - attack.defense-evasion
    - attack.t1036.006
logsource:
    product: macos
    category: process_creation
detection:
    selection1:
        CommandLine|endswith: ' '
    selection2:
        Image|endswith: ' '
    condition: 1 of selection*
falsepositives:
    - Mistyped commands or legitimate binaries named to match the pattern
level: low
```
