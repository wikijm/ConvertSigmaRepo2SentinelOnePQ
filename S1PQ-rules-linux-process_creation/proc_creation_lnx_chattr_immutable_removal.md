```sql
// Translated content (automatically translated on 22-12-2025 01:02:22):
event.type="Process Creation" and (endpoint.os="linux" and (tgt.process.image.path contains "/chattr" and tgt.process.cmdline contains " -i "))
```


# Original Sigma Rule:
```yaml
title: Remove Immutable File Attribute
id: 34979410-e4b5-4e5d-8cfb-389fdff05c12
related:
    - id: a5b977d6-8a81-4475-91b9-49dbfcd941f7
      type: derived
status: test
description: Detects usage of the 'chattr' utility to remove immutable file attribute.
references:
    - https://www.trendmicro.com/en_us/research/22/i/how-malicious-actors-abuse-native-linux-tools-in-their-attacks.html
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-09-15
tags:
    - attack.defense-evasion
    - attack.t1222.002
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|endswith: '/chattr'
        CommandLine|contains: ' -i '
    condition: selection
falsepositives:
    - Administrator interacting with immutable files (e.g. for instance backups).
level: medium
```
