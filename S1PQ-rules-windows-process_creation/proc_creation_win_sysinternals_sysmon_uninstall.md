```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (((tgt.process.image.path contains "\\Sysmon64.exe" or tgt.process.image.path contains "\\Sysmon.exe") or tgt.process.displayName="System activity monitor") and (tgt.process.cmdline contains "-u" or tgt.process.cmdline contains "/u" or tgt.process.cmdline contains "–u" or tgt.process.cmdline contains "—u" or tgt.process.cmdline contains "―u")))
```


# Original Sigma Rule:
```yaml
title: Uninstall Sysinternals Sysmon
id: 6a5f68d1-c4b5-46b9-94ee-5324892ea939
status: test
description: Detects the removal of Sysmon, which could be a potential attempt at defense evasion
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.001/T1562.001.md#atomic-test-11---uninstall-sysmon
author: frack113
date: 2022-01-12
modified: 2024-03-13
tags:
    - attack.defense-evasion
    - attack.t1562.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_pe:
        - Image|endswith:
              - \Sysmon64.exe
              - \Sysmon.exe
        - Description: 'System activity monitor'
    selection_cli:
        CommandLine|contains|windash: '-u'
    condition: all of selection_*
falsepositives:
    - Legitimate administrators might use this command to remove Sysmon for debugging purposes
level: high
```
