```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains "winzip.exe" or tgt.process.cmdline contains "winzip64.exe") and tgt.process.cmdline contains "-s\"" and (tgt.process.cmdline contains " -min " or tgt.process.cmdline contains " -a ")))
```


# Original Sigma Rule:
```yaml
title: Compress Data and Lock With Password for Exfiltration With WINZIP
id: e2e80da2-8c66-4e00-ae3c-2eebd29f6b6d
status: test
description: An adversary may compress or encrypt data that is collected prior to exfiltration using 3rd party utilities
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1560.001/T1560.001.md
author: frack113
date: 2021-07-27
modified: 2022-12-25
tags:
    - attack.collection
    - attack.t1560.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_winzip:
        CommandLine|contains:
            - 'winzip.exe'
            - 'winzip64.exe'
    selection_password:
        CommandLine|contains: '-s"'
    selection_other:
        CommandLine|contains:
            - ' -min '
            - ' -a '
    condition: all of selection*
falsepositives:
    - Unknown
level: medium
```
