```sql
// Translated content (automatically translated on 02-08-2025 00:59:06):
event.type="Process Creation" and (endpoint.os="linux" and (tgt.process.image.path contains "crontab" and tgt.process.cmdline contains "/tmp/"))
```


# Original Sigma Rule:
```yaml
title: Scheduled Cron Task/Job - Linux
id: 6b14bac8-3e3a-4324-8109-42f0546a347f
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
    product: linux
detection:
    selection:
        Image|endswith: 'crontab'
        CommandLine|contains: '/tmp/'
    condition: selection
falsepositives:
    - Legitimate administration activities
level: medium
```
