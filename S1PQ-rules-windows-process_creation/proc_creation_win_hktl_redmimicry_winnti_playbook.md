```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\\rundll32.exe" or tgt.process.image.path contains "\\cmd.exe") and (tgt.process.cmdline contains "gthread-3.6.dll" or tgt.process.cmdline contains "\\Windows\\Temp\\tmp.bat" or tgt.process.cmdline contains "sigcmm-2.4.dll")))
```


# Original Sigma Rule:
```yaml
title: HackTool - RedMimicry Winnti Playbook Execution
id: 95022b85-ff2a-49fa-939a-d7b8f56eeb9b
status: test
description: Detects actions caused by the RedMimicry Winnti playbook a automated breach emulations utility
references:
    - https://redmimicry.com/posts/redmimicry-winnti/
author: Alexander Rausch
date: 2020-06-24
modified: 2023-03-01
tags:
    - attack.execution
    - attack.defense-evasion
    - attack.t1106
    - attack.t1059.003
    - attack.t1218.011
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith:
            - '\rundll32.exe'
            - '\cmd.exe'
        CommandLine|contains:
            - 'gthread-3.6.dll'
            - '\Windows\Temp\tmp.bat'
            - 'sigcmm-2.4.dll'
    condition: selection
falsepositives:
    - Unknown
level: high
```
