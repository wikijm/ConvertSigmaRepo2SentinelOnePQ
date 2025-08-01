```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains "/EXEFilename" or tgt.process.cmdline contains "/CommandLine") and ((tgt.process.cmdline contains " /RunAs 8 " or tgt.process.cmdline contains " /RunAs 4 " or tgt.process.cmdline contains " /RunAs 10 " or tgt.process.cmdline contains " /RunAs 11 ") or (tgt.process.cmdline contains "/RunAs 8" or tgt.process.cmdline contains "/RunAs 4" or tgt.process.cmdline contains "/RunAs 10" or tgt.process.cmdline contains "/RunAs 11"))))
```


# Original Sigma Rule:
```yaml
title: PUA - AdvancedRun Suspicious Execution
id: fa00b701-44c6-4679-994d-5a18afa8a707
related:
    - id: d2b749ee-4225-417e-b20e-a8d2193cbb84
      type: similar
status: test
description: Detects the execution of AdvancedRun utility in the context of the TrustedInstaller, SYSTEM, Local Service or Network Service accounts
references:
    - https://twitter.com/splinter_code/status/1483815103279603714
    - https://medium.com/s2wblog/analysis-of-destructive-malware-whispergate-targeting-ukraine-9d5d158f19f3
    - https://www.elastic.co/security-labs/operation-bleeding-bear
    - https://www.winhelponline.com/blog/run-program-as-system-localsystem-account-windows/
author: Florian Roth (Nextron Systems)
date: 2022-01-20
modified: 2023-02-21
tags:
    - attack.defense-evasion
    - attack.privilege-escalation
    - attack.t1134.002
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - '/EXEFilename'
            - '/CommandLine'
    selection_runas:
        - CommandLine|contains:
              - ' /RunAs 8 '
              - ' /RunAs 4 '
              - ' /RunAs 10 '
              - ' /RunAs 11 '
        - CommandLine|endswith:
              - '/RunAs 8'
              - '/RunAs 4'
              - '/RunAs 10'
              - '/RunAs 11'
    condition: all of selection*
falsepositives:
    - Unknown
level: high
```
