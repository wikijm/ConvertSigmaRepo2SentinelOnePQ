```sql
// Translated content (automatically translated on 30-07-2025 01:27:40):
event.type="Process Creation" and (endpoint.os="osx" and (tgt.process.image.path contains "/crontab" and tgt.process.cmdline contains "/tmp/"))
```


# Original Sigma Rule:
```yaml
title: Scheduled Cron Task/Job - MacOs
id: 7c3b43d8-d794-47d2-800a-d277715aa460
status: test
description: Detects abuse of the cron utility to perform task scheduling for initial or recurring execution of malicious code. Detection will focus on crontab jobs uploaded from the tmp folder.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1053.003/T1053.003.md
author: Alejandro Ortuno, oscd.community
date: 2020-10-06
modified: 2022-11-27
tags:
    - attack.execution
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1053.003
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        Image|endswith: '/crontab'
        CommandLine|contains: '/tmp/'
    condition: selection
falsepositives:
    - Legitimate administration activities
level: medium
```
