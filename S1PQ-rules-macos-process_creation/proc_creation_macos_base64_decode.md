```sql
// Translated content (automatically translated on 22-12-2025 01:26:43):
event.type="Process Creation" and (endpoint.os="osx" and (tgt.process.image.path="/usr/bin/base64" and tgt.process.cmdline contains "-d"))
```


# Original Sigma Rule:
```yaml
title: Decode Base64 Encoded Text -MacOs
id: 719c22d7-c11a-4f2c-93a6-2cfdd5412f68
status: test
description: Detects usage of base64 utility to decode arbitrary base64-encoded text
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1027/T1027.md
author: Daniil Yugoslavskiy, oscd.community
date: 2020-10-19
modified: 2022-11-26
tags:
    - attack.defense-evasion
    - attack.t1027
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        Image: '/usr/bin/base64'
        CommandLine|contains: '-d'
    condition: selection
falsepositives:
    - Legitimate activities
level: low
```
