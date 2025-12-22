```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\\Psr.exe" and (tgt.process.cmdline contains "/start" or tgt.process.cmdline contains "-start")))
```


# Original Sigma Rule:
```yaml
title: Screen Capture Activity Via Psr.EXE
id: 2158f96f-43c2-43cb-952a-ab4580f32382
status: test
description: Detects execution of Windows Problem Steps Recorder (psr.exe), a utility used to record the user screen and clicks.
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Psr/
    - https://web.archive.org/web/20200229201156/https://www.sans.org/cyber-security-summit/archives/file/summit-archive-1493861893.pdf
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1560.001/T1560.001.md
author: Beyu Denis, oscd.community
date: 2019-10-12
modified: 2024-01-04
tags:
    - attack.collection
    - attack.t1113
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\Psr.exe'
        CommandLine|contains:
            - '/start'
            - '-start'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
