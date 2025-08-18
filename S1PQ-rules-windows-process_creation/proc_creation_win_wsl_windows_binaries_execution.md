```sql
// Translated content (automatically translated on 18-08-2025 02:21:52):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path matches "[a-zA-Z]:\\\\" and tgt.process.image.path contains "\\\\wsl.localhost"))
```


# Original Sigma Rule:
```yaml
title: Windows Binary Executed From WSL
id: ed825c86-c009-4014-b413-b76003e33d35
status: test
description: |
    Detects the execution of Windows binaries from within a WSL instance.
    This could be used to masquerade parent-child relationships
references:
    - Internal Research
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-02-14
tags:
    - attack.execution
    - attack.defense-evasion
    - attack.t1202
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|re: '[a-zA-Z]:\\'
        CurrentDirectory|contains: '\\\\wsl.localhost' # Note: programs not supporting UNC paths (example: cmd.exe). Will default to another location
    condition: selection
falsepositives:
    - Unknown
level: medium
```
