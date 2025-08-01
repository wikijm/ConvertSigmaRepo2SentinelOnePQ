```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\SharpEvtMute.exe" or tgt.process.displayName="SharpEvtMute" or (tgt.process.cmdline contains "--Filter \"rule " or tgt.process.cmdline contains "--Encoded --Filter \\"")))
```


# Original Sigma Rule:
```yaml
title: HackTool - SharpEvtMute Execution
id: bedfc8ad-d1c7-4e37-a20e-e2b0dbee759c
related:
    - id: 49329257-089d-46e6-af37-4afce4290685 # DLL load
      type: similar
status: test
description: Detects the use of SharpEvtHook, a tool that tampers with the Windows event logs
references:
    - https://github.com/bats3c/EvtMute
author: Florian Roth (Nextron Systems)
date: 2022-09-07
modified: 2023-02-14
tags:
    - attack.defense-evasion
    - attack.t1562.002
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        - Image|endswith: '\SharpEvtMute.exe'
        - Description: 'SharpEvtMute'
        - CommandLine|contains:
              - '--Filter "rule '
              - '--Encoded --Filter \"'
    condition: selection
falsepositives:
    - Unknown
level: high
```
