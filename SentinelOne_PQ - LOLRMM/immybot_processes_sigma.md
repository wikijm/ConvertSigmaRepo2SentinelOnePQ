```sql
// Translated content (automatically translated on 10-09-2026 01:58:18):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\\ImmyAgent.exe" or src.process.image.path contains "\\ImmyUpdater.exe" or src.process.image.path contains "\\ImmyBot.Agent.Ephemeral.exe") or (tgt.process.image.path contains "\\ImmyAgent.exe" or tgt.process.image.path contains "\\ImmyUpdater.exe" or tgt.process.image.path contains "\\ImmyBot.Agent.Ephemeral.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential ImmyBot RMM Tool Process Activity
id: cb300985-1903-52c0-8d14-f514636826a5
status: experimental
description: |
    Detects potential processes activity of ImmyBot RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-05-18
modified: 2026-09-02
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith:
            - '\\ImmyAgent.exe'
            - '\\ImmyUpdater.exe'
            - '\\ImmyBot.Agent.Ephemeral.exe'
    selection_image:
        Image|endswith:
            - '\\ImmyAgent.exe'
            - '\\ImmyUpdater.exe'
            - '\\ImmyBot.Agent.Ephemeral.exe'
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of ImmyBot
level: medium
```
