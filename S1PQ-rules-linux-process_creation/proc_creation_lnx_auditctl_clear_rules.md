```sql
// Translated content (automatically translated on 22-12-2025 01:02:22):
event.type="Process Creation" and (endpoint.os="linux" and (tgt.process.image.path contains "/auditctl" and tgt.process.cmdline matches "-D"))
```


# Original Sigma Rule:
```yaml
title: Audit Rules Deleted Via Auditctl
id: bed26dea-4525-47f4-b24a-76e30e44ffb0
status: experimental
description: |
    Detects the execution of 'auditctl' with the '-D' command line parameter, which deletes all configured audit rules and watches on Linux systems.
    This technique is commonly used by attackers to disable audit logging and cover their tracks by removing monitoring capabilities.
    Removal of audit rules can significantly impair detection of malicious activities on the affected system.
references:
    - https://www.atomicredteam.io/atomic-red-team/atomics/T1562.012
    - https://linux.die.net/man/8/auditct
author: Mohamed LAKRI
date: 2025-10-17
tags:
    - attack.defense-evasion
    - attack.t1562.012
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|endswith: '/auditctl'
        CommandLine|re: '-D'
    condition: selection
falsepositives:
    - An administrator troubleshooting. Investigate all attempts.
level: high
```
