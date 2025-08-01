```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\regsvr32.exe" and (tgt.process.cmdline contains " -i:" or tgt.process.cmdline contains " /i:" or tgt.process.cmdline contains " –i:" or tgt.process.cmdline contains " —i:" or tgt.process.cmdline contains " ―i:")) and (not tgt.process.cmdline contains " -n " or tgt.process.cmdline contains " /n " or tgt.process.cmdline contains " –n " or tgt.process.cmdline contains " —n " or tgt.process.cmdline contains " ―n ")))
```


# Original Sigma Rule:
```yaml
title: Potential Regsvr32 Commandline Flag Anomaly
id: b236190c-1c61-41e9-84b3-3fe03f6d76b0
status: test
description: Detects a potential command line flag anomaly related to "regsvr32" in which the "/i" flag is used without the "/n" which should be uncommon.
references:
    - https://twitter.com/sbousseaden/status/1282441816986484737?s=12
author: Florian Roth (Nextron Systems)
date: 2019-07-13
modified: 2024-03-13
tags:
    - attack.defense-evasion
    - attack.t1218.010
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\regsvr32.exe'
        CommandLine|contains|windash: ' -i:'
    filter_main_flag:
        CommandLine|contains|windash: ' -n '
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Administrator typo might cause some false positives
level: medium
```
