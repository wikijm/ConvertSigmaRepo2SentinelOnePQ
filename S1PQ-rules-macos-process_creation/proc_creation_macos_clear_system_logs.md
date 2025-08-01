```sql
// Translated content (automatically translated on 02-08-2025 01:23:44):
event.type="Process Creation" and (endpoint.os="osx" and ((tgt.process.image.path contains "/rm" or tgt.process.image.path contains "/unlink" or tgt.process.image.path contains "/shred") and (tgt.process.cmdline contains "/var/log" or (tgt.process.cmdline contains "/Users/" and tgt.process.cmdline contains "/Library/Logs/"))))
```


# Original Sigma Rule:
```yaml
title: Indicator Removal on Host - Clear Mac System Logs
id: acf61bd8-d814-4272-81f0-a7a269aa69aa
status: test
description: Detects deletion of local audit logs
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1070.002/T1070.002.md
author: remotephone, oscd.community
date: 2020-10-11
modified: 2022-09-16
tags:
    - attack.defense-evasion
    - attack.t1070.002
logsource:
    product: macos
    category: process_creation
detection:
    selection1:
        Image|endswith:
            - '/rm'
            - '/unlink'
            - '/shred'
    selection_cli_1:
        CommandLine|contains: '/var/log'
    selection_cli_2:
        CommandLine|contains|all:
            - '/Users/'
            - '/Library/Logs/'
    condition: selection1 and 1 of selection_cli*
falsepositives:
    - Legitimate administration activities
level: medium
```
