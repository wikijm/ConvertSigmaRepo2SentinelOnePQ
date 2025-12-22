```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\\DumpStack.log" or tgt.process.cmdline contains " -o DumpStack.log"))
```


# Original Sigma Rule:
```yaml
title: DumpStack.log Defender Evasion
id: 4f647cfa-b598-4e12-ad69-c68dd16caef8
status: test
description: Detects the use of the filename DumpStack.log to evade Microsoft Defender
references:
    - https://twitter.com/mrd0x/status/1479094189048713219
author: Florian Roth (Nextron Systems)
date: 2022-01-06
modified: 2022-06-17
tags:
    - attack.defense-evasion
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\DumpStack.log'
    selection_download:
        CommandLine|contains: ' -o DumpStack.log'
    condition: 1 of selection*
falsepositives:
    - Unknown
level: critical
```
