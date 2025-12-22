```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\\shutdown.exe" and tgt.process.cmdline contains "/l"))
```


# Original Sigma Rule:
```yaml
title: Suspicious Execution of Shutdown to Log Out
id: ec290c06-9b6b-4338-8b6b-095c0f284f10
status: test
description: Detects the rare use of the command line tool shutdown to logoff a user
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/9e5b12c4912c07562aec7500447b11fa3e17e254/atomics/T1529/T1529.md
    - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/shutdown
author: frack113
date: 2022-10-01
tags:
    - attack.impact
    - attack.t1529
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\shutdown.exe'
        CommandLine|contains: '/l'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
