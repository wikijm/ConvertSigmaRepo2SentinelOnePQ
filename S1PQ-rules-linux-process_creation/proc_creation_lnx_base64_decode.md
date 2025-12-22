```sql
// Translated content (automatically translated on 22-12-2025 01:02:22):
event.type="Process Creation" and (endpoint.os="linux" and (tgt.process.image.path contains "/base64" and tgt.process.cmdline contains "-d"))
```


# Original Sigma Rule:
```yaml
title: Decode Base64 Encoded Text
id: e2072cab-8c9a-459b-b63c-40ae79e27031
status: test
description: Detects usage of base64 utility to decode arbitrary base64-encoded text
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1027/T1027.md
author: Daniil Yugoslavskiy, oscd.community
date: 2020-10-19
modified: 2021-11-27
tags:
    - attack.defense-evasion
    - attack.t1027
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: '/base64'
        CommandLine|contains: '-d' # Also covers "--decode"
    condition: selection
falsepositives:
    - Legitimate activities
level: low
```
