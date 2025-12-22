```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\\shutdown.exe" and (tgt.process.cmdline contains "/r " or tgt.process.cmdline contains "/s ")))
```


# Original Sigma Rule:
```yaml
title: Suspicious Execution of Shutdown
id: 34ebb878-1b15-4895-b352-ca2eeb99b274
status: test
description: Use of the commandline to shutdown or reboot windows
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1529/T1529.md
    - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/shutdown
author: frack113
date: 2022-01-01
tags:
    - attack.impact
    - attack.t1529
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\shutdown.exe'
        CommandLine|contains:
            - '/r '
            - '/s '
    condition: selection
falsepositives:
    - Unknown
level: medium
```
