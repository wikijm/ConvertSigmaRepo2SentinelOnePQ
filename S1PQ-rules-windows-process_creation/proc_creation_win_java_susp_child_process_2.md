```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\\java.exe" and (tgt.process.image.path contains "\\bash.exe" or tgt.process.image.path contains "\\cmd.exe" or tgt.process.image.path contains "\\powershell.exe" or tgt.process.image.path contains "\\pwsh.exe")) and (not (src.process.image.path contains "build" and tgt.process.cmdline contains "build"))))
```


# Original Sigma Rule:
```yaml
title: Shell Process Spawned by Java.EXE
id: dff1e1cc-d3fd-47c8-bfc2-aeb878a754c0
related:
    - id: 0d34ed8b-1c12-4ff2-828c-16fc860b766d
      type: similar
status: test
description: Detects shell spawned from Java host process, which could be a sign of exploitation (e.g. log4j exploitation)
references:
    - https://web.archive.org/web/20231230220738/https://www.lunasec.io/docs/blog/log4j-zero-day/
author: Andreas Hunkeler (@Karneades), Nasreddine Bencherchali
date: 2021-12-17
modified: 2024-01-18
tags:
    - attack.initial-access
    - attack.persistence
    - attack.privilege-escalation
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\java.exe'
        Image|endswith:
            - '\bash.exe'
            - '\cmd.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
    filter_main_build:
        ParentImage|contains: 'build'  # excluding CI build agents
        CommandLine|contains: 'build'  # excluding CI build agents
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Legitimate calls to system binaries
    - Company specific internal usage
level: medium
```
