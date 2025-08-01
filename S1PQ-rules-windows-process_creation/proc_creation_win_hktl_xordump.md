```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\xordump.exe" or (tgt.process.cmdline contains " -process lsass.exe " or tgt.process.cmdline contains " -m comsvcs " or tgt.process.cmdline contains " -m dbghelp " or tgt.process.cmdline contains " -m dbgcore ")))
```


# Original Sigma Rule:
```yaml
title: HackTool - XORDump Execution
id: 66e563f9-1cbd-4a22-a957-d8b7c0f44372
status: test
description: Detects suspicious use of XORDump process memory dumping utility
references:
    - https://github.com/audibleblink/xordump
author: Florian Roth (Nextron Systems)
date: 2022-01-28
modified: 2023-02-08
tags:
    - attack.defense-evasion
    - attack.t1036
    - attack.t1003.001
    - attack.credential-access
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\xordump.exe'
        - CommandLine|contains:
              - ' -process lsass.exe '
              - ' -m comsvcs '
              - ' -m dbghelp '
              - ' -m dbgcore '
    condition: selection
falsepositives:
    - Another tool that uses the command line switches of XORdump
level: high
```
