```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\sqldumper.exe" and (tgt.process.cmdline contains "0x0110" or tgt.process.cmdline contains "0x01100:40")))
```


# Original Sigma Rule:
```yaml
title: Dumping Process via Sqldumper.exe
id: 23ceaf5c-b6f1-4a32-8559-f2ff734be516
status: test
description: Detects process dump via legitimate sqldumper.exe binary
references:
    - https://twitter.com/countuponsec/status/910977826853068800
    - https://twitter.com/countuponsec/status/910969424215232518
    - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Sqldumper/
author: Kirill Kiryanov, oscd.community
date: 2020-10-08
modified: 2021-11-27
tags:
    - attack.credential-access
    - attack.t1003.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\sqldumper.exe'
        CommandLine|contains:
            - '0x0110'
            - '0x01100:40'
    condition: selection
falsepositives:
    - Legitimate MSSQL Server actions
level: medium
```
