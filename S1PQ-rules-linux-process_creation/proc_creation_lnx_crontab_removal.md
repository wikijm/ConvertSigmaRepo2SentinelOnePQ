```sql
// Translated content (automatically translated on 17-06-2025 00:57:21):
event.type="Process Creation" and (endpoint.os="linux" and (tgt.process.image.path contains "crontab" and tgt.process.cmdline contains " -r"))
```


# Original Sigma Rule:
```yaml
title: Remove Scheduled Cron Task/Job
id: c2e234de-03a3-41e1-b39a-1e56dc17ba67
status: test
description: |
    Detects usage of the 'crontab' utility to remove the current crontab.
    This is a common occurrence where cryptocurrency miners compete against each other by removing traces of other miners to hijack the maximum amount of resources possible
references:
    - https://www.trendmicro.com/en_us/research/22/i/how-malicious-actors-abuse-native-linux-tools-in-their-attacks.html
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-09-15
tags:
    - attack.defense-evasion
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|endswith: 'crontab'
        CommandLine|contains: ' -r'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
