```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains "for /f" and tgt.process.cmdline contains "tokens=" and tgt.process.cmdline contains "in (" and tgt.process.cmdline contains "dir") or (src.process.cmdline contains "for /f" and src.process.cmdline contains "tokens=" and src.process.cmdline contains "in (" and src.process.cmdline contains "dir")))
```


# Original Sigma Rule:
```yaml
title: Suspicious Usage of For Loop with Recursive Directory Search in CMD
id: 2782fbd8-b662-4eb5-9962-5bfbfb671e7b
status: experimental
description: |
    Detects suspicious usage of the cmd.exe 'for /f' loop combined with the 'tokens=' parameter and a recursive directory listing.
    This pattern may indicate an attempt to discover and execute system binaries dynamically, for example powershell, a technique sometimes used by attackers to evade detection.
    This behavior has been observed in various malicious lnk files.
references:
    - https://www.virustotal.com/gui/file/29837d0d3202758063185828c8f8d9e0b7b42b365c8941cc926d2d7c7bae2fb3
author: Joseliyo Sanchez, @Joseliyo_Jstnk
date: 2025-11-12
tags:
    - attack.execution
    - attack.t1059.003
    - attack.defense-evasion
    - attack.t1027.010
logsource:
    category: process_creation
    product: windows
detection:
    selection_tokens:
        CommandLine|contains|all:
            - 'for /f'
            - 'tokens='
            - 'in ('
            - 'dir'
    selection_tokens_parent:
        ParentCommandLine|contains|all:
            - 'for /f'
            - 'tokens='
            - 'in ('
            - 'dir'
    condition: 1 of selection_*
falsepositives:
    - Unknown
level: medium
```
