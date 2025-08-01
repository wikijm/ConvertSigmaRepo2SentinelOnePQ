```sql
// Translated content (automatically translated on 02-08-2025 00:59:06):
event.type="Process Creation" and (endpoint.os="linux" and ((tgt.process.image.path contains "/rm" or tgt.process.image.path contains "/shred" or tgt.process.image.path contains "/unlink") and (tgt.process.cmdline contains "/var/log" or tgt.process.cmdline contains "/var/spool/mail")))
```


# Original Sigma Rule:
```yaml
title: Clear Linux Logs
id: 80915f59-9b56-4616-9de0-fd0dea6c12fe
status: stable
description: Detects attempts to clear logs on the system. Adversaries may clear system logs to hide evidence of an intrusion
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1070.002/T1070.002.md
author: Ömer Günal, oscd.community
date: 2020-10-07
modified: 2022-09-15
tags:
    - attack.defense-evasion
    - attack.t1070.002
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|endswith:
            - '/rm'    # covers /rmdir as well
            - '/shred'
            - '/unlink'
        CommandLine|contains:
            - '/var/log'
            - '/var/spool/mail'
    condition: selection
falsepositives:
    - Legitimate administration activities
level: medium
```
