```sql
// Translated content (automatically translated on 02-08-2025 00:52:11):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\conhost.exe" and src.process.cmdline contains "--headless"))
```


# Original Sigma Rule:
```yaml
title: Headless Process Launched Via Conhost.EXE
id: 00ca75ab-d5ce-43be-b86c-55ff39c6abfc
related:
    - id: 056c7317-9a09-4bd4-9067-d051312752ea
      type: derived
status: test
description: |
    Detects the launch of a child process via "conhost.exe" with the "--headless" flag.
    The "--headless" flag hides the windows from the user upon execution.
references:
    - https://www.huntress.com/blog/fake-browser-updates-lead-to-boinc-volunteer-computing-software
author: Nasreddine Bencherchali (Nextron Systems)
date: 2024-07-23
tags:
    - attack.defense-evasion
    - attack.t1059.001
    - attack.t1059.003
    - detection.threat-hunting
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\conhost.exe'
        ParentCommandLine|contains: '--headless'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
