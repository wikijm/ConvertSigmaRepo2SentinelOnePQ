```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains " /lockscreenurl:" and (not (tgt.process.cmdline contains ".jpg" or tgt.process.cmdline contains ".jpeg" or tgt.process.cmdline contains ".png"))) or (tgt.process.cmdline contains "reg delete" and tgt.process.cmdline contains "\PersonalizationCSP"))) | columns tgt.process.cmdline,src.process.cmdline
```


# Original Sigma Rule:
```yaml
title: Suspicious Desktopimgdownldr Command
id: bb58aa4a-b80b-415a-a2c0-2f65a4c81009
status: test
description: Detects a suspicious Microsoft desktopimgdownldr execution with parameters used to download files from the Internet
references:
    - https://labs.sentinelone.com/living-off-windows-land-a-new-native-file-downldr/
    - https://twitter.com/SBousseaden/status/1278977301745741825
author: Florian Roth (Nextron Systems)
date: 2020-07-03
modified: 2021-11-27
tags:
    - attack.command-and-control
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine|contains: ' /lockscreenurl:'
    selection1_filter:
        CommandLine|contains:
            - '.jpg'
            - '.jpeg'
            - '.png'
    selection_reg:
        CommandLine|contains|all:
            - 'reg delete'
            - '\PersonalizationCSP'
    condition: ( selection1 and not selection1_filter ) or selection_reg
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
level: high
```
