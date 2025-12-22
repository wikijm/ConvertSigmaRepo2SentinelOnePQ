```sql
// Translated content (automatically translated on 22-12-2025 01:26:43):
event.type="Process Creation" and (endpoint.os="osx" and ((tgt.process.image.path contains "/grep" and tgt.process.cmdline contains "password") or tgt.process.cmdline contains "laZagne"))
```


# Original Sigma Rule:
```yaml
title: Credentials In Files
id: 53b1b378-9b06-4992-b972-dde6e423d2b4
status: test
description: Detecting attempts to extract passwords with grep and laZagne
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1552.001/T1552.001.md
author: 'Igor Fits, Mikhail Larin, oscd.community'
date: 2020-10-19
modified: 2021-11-27
tags:
    - attack.credential-access
    - attack.t1552.001
logsource:
    product: macos
    category: process_creation
detection:
    selection1:
        Image|endswith: '/grep'
        CommandLine|contains: 'password'
    selection2:
        CommandLine|contains: 'laZagne'
    condition: 1 of selection*
falsepositives:
    - Unknown
level: high
```
