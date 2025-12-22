```sql
// Translated content (automatically translated on 22-12-2025 01:02:22):
event.type="Process Creation" and (endpoint.os="linux" and (tgt.process.cmdline contains "chown root" and (tgt.process.cmdline contains " chmod u+s" or tgt.process.cmdline contains " chmod g+s")))
```


# Original Sigma Rule:
```yaml
title: Setuid and Setgid
id: c21c4eaa-ba2e-419a-92b2-8371703cbe21
status: test
description: Detects suspicious change of file privileges with chown and chmod commands
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1548.001/T1548.001.md
author: Ömer Günal
date: 2020-06-16
modified: 2022-10-05
tags:
    - attack.defense-evasion
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1548.001
logsource:
    product: linux
    category: process_creation
detection:
    selection_root:
        CommandLine|contains: 'chown root'
    selection_perm:
        CommandLine|contains:
            - ' chmod u+s'
            - ' chmod g+s'
    condition: all of selection_*
falsepositives:
    - Legitimate administration activities
level: low
```
